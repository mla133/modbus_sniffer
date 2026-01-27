# src/cli/modbus_watch.py
import sys
import signal
import argparse
from datetime import timezone, datetime
from pathlib import Path

import pyshark

from modbus.direction import normalize_func_code, get_packet_endpoints
from modbus.registers import parse_register_map
from modbus.coils import parse_fc5, parse_fc15
from app_logging import log_err, log_info  # _ts not used
from mqtt.client import init_mqtt, mqtt_publish  # safe even if paho missing


def _build_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="modbus-watch",
        description=(
            "Watch Modbus packets (PCAP or live). "
            "If --trigger-change-reg is provided, publish to MQTT only when that register's value changes; "
            "otherwise just print watched values."
        ),
    )

    # Source selection
    srcdst = ap.add_argument_group("source")
    srcdst.add_argument("--pcap", help="PCAP/PCAPNG file to replay")
    srcdst.add_argument("--iface", help='Live interface name, e.g. "Ethernet 4"')

    # Filters
    filt = ap.add_argument_group("filters")
    filt.add_argument(
        "--fc",
        type=int,
        default=3,
        choices=[3, 4, 5, 15],
        help="Modbus function code to watch (3, 4, 5, or 15). Default: 3",
    )
    filt.add_argument("--src", help="Only packets with this source IP")
    filt.add_argument("--dst", help="Only packets with this destination IP")

    # Watch set (console printing only)
    watch = ap.add_argument_group("watch set")
    watch.add_argument(
        "--watch",
        nargs="+",
        type=int,
        default=[100] + list(range(200, 211)),
        help="Registers/Coils to print. Used for FC=3/4 (registers) and FC=5/15 (coils). Default: 100 and 200..210",
    )
    ap.add_argument(
        "--deltas-only",
        action="store_true",
        help="Print only when watched values change from their last seen value",
    )

    # Edge-triggered publishing (optional)
    trig = ap.add_argument_group("edge trigger (publish on change)")
    trig.add_argument(
        "--trigger-change-reg",
        type=int,
        help="Register address to publish on any value change (FC=3/4). If omitted, no MQTT publishes happen.",
    )
    trig.add_argument(
        "--trigger-once",
        action="store_true",
        help="Publish only the first time the trigger condition is met (first change)",
    )

    # Context to include when the trigger fires (e.g., 200 and 205)
    ap.add_argument(
        "--include-regs",
        nargs="+",
        type=int,
        default=[200, 205],
        help="Register addresses whose latest values will be included in the MQTT payload when the trigger fires. Default: 200 205",
    )

    # Diagnostics / payload
    ap.add_argument(
        "--payload-format",
        choices=["json", "text"],
        default="json",
        help="Publish JSON dict (default) or simple text payload",
    )
    ap.add_argument(
        "--trace-triggers",
        action="store_true",
        help="Log why triggers did or didn't fire (diagnostic)",
    )
    ap.add_argument(
        "--echo-trigger",
        action="store_true",
        help="Also include the trigger register in console output (adds it to --watch)",
    )

    # --- Session logging of all Modbus traffic between two register states ---
    loggrp = ap.add_argument_group("session logging")
    loggrp.add_argument(
        "--session-log",
        action="store_true",
        help="Enable session logging: start a new log file when a register changes to start-val, "
             "log ALL Modbus traffic, and stop when it changes to stop-val.",
    )
    loggrp.add_argument(
        "--log-dir",
        default="logs",
        help="Directory to write session logs (default: ./logs)",
    )
    loggrp.add_argument(
        "--session-start-reg",
        type=int,
        default=100,
        help="Register to watch for session start (default: 100)",
    )
    loggrp.add_argument(
        "--session-start-val",
        type=int,
        default=3,
        help="Register value that starts a session (default: 3)",
    )
    loggrp.add_argument(
        "--session-stop-val",
        type=int,
        default=4,
        help="Register value that stops a session (default: 4)",
    )

    return ap.parse_args(argv)


def _build_payload(args, ts, src, dst, fc, trigger_reg, trigger_val, context_regs):
    """
    Return payload for mqtt_publish(payload):
    - if args.payload_format == 'json': dict (client.py json.dumps it)
    - else: str
    """
    if args.payload_format == "text":
        ctx = ", ".join(f"{k}={v}" for k, v in sorted(context_regs.items()))
        return f"{ts} {src}->{dst} fc={fc} reg={trigger_reg} value={trigger_val} ctx[{ctx}]"
    # JSON dict (mqtt client json.dumps it)
    return {
        "ts": ts,
        "src": src,
        "dst": dst,
        "fc": fc,
        "reg": trigger_reg,
        "value": trigger_val,
        "context": context_regs,
    }


def main(argv=None):
    args = _build_args(argv)
    if not (args.pcap or args.iface):
        log_err("Choose one: --pcap <file> or --iface <name>")
        return 2

    # Initialize shared MQTT client (reads config.py).
    # Safe to call even if we never publish.
    init_mqtt()  # mqtt_publish encodes dict payload to JSON and publishes (QoS=1).

    trigger_fired = False  # for --trigger-once
    last_published_reg = {}  # reg -> last value we actually published (edge trigger)

    # Session logging state
    session_active = False
    session_file = None
    prev_start_reg_val = None  # previous observed value for session-start-reg (edge detection)

    def _now_name() -> str:
        # UTC timestamped filename: YYYY-MM-DD_HH-MM-SS.txt
        return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S") + ".txt"

    def _open_session():
        nonlocal session_active, session_file
        try:
            Path(args.log_dir).mkdir(parents=True, exist_ok=True)
            fname = Path(args.log_dir) / _now_name()
            session_file = fname.open("w", encoding="utf-8")
            session_active = True
            log_info(f"[+] Session log started: {fname}")
        except Exception as e:
            log_err(f"Failed to open session log: {e}")

    def _close_session():
        nonlocal session_active, session_file
        if session_file:
            try:
                session_file.flush()
                session_file.close()
            except Exception:
                pass
        session_file = None
        if session_active:
            log_info("[+] Session log stopped")
        session_active = False

    def _write_session(line: str):
        if session_active and session_file:
            try:
                session_file.write(line + "\n")
                session_file.flush()
            except Exception as e:
                log_err(f"Session write error: {e}")

    # Wireshark display filter (post-capture filter)
    display_df = "modbus && tcp.port == 502"
    if args.src:
        display_df += f" && ip.src == {args.src}"
    if args.dst:
        display_df += f" && ip.dst == {args.dst}"

    cap = None
    try:
        if args.pcap:
            cap = pyshark.FileCapture(args.pcap, display_filter=display_df, keep_packets=False)
            iterator = cap
            log_info(f"[+] Replaying PCAP: {args.pcap}")
        else:
            bpf = "tcp port 502"
            cap = pyshark.LiveCapture(interface=args.iface, display_filter=display_df, bpf_filter=bpf)
            iterator = cap.sniff_continuously()
            log_info(f"[+] Live on {args.iface} (Ctrl-C to stop)")

        WATCH = set(args.watch)
        if args.echo_trigger and args.trigger_change_reg is not None:
            WATCH.add(args.trigger_change_reg)

        # State caches
        REG_STATE = {}  # used for console delta printing of WATCHed registers
        REG_LAST = {}   # last seen value for ANY register (for context payloads)
        COIL_STATE = {} # used for deltas-only for coils

        def _stop(sig, frame):
            log_info("\n[!] Stopping...")
            try:
                if cap:
                    cap.close()
            finally:
                # Ensure any active session file is closed
                _close_session()
                sys.exit(0)

        signal.signal(signal.SIGINT, _stop)

        for pkt in iterator:
            if not hasattr(pkt, "modbus"):
                continue

            m = pkt.modbus
            fc = normalize_func_code(m)
            src, dst, _, _ = get_packet_endpoints(pkt)
            wall = pkt.sniff_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            # --- Session logging: detect start/stop edges on start-reg using FC 3/4 frames ---
            # Also write ALL Modbus traffic (FC 3/4/5/15) to the session file while active.
            registers_for_watch = None  # reuse if fc in (3,4)

            if fc in (3, 4):
                registers = parse_register_map(m, fc=fc) or {}
                registers_for_watch = registers  # reuse later for watch print

                if args.session_log:
                    key = args.session_start_reg
                    if key in registers:
                        cur = registers[key]
                        # FIRST observation: if it already equals the start value, open a session now
                        if prev_start_reg_val is None:
                            if cur == args.session_start_val and not session_active:
                                _open_session()
                            prev_start_reg_val = cur
                        # Subsequent observation: open on not-start -> start transition
                        elif (not session_active) and (prev_start_reg_val != args.session_start_val) and (cur == args.session_start_val):
                            _open_session()
                            prev_start_reg_val = cur
                        # Stop: when active and we observe a transition to stop value
                        elif session_active and (prev_start_reg_val != args.session_stop_val) and (cur == args.session_stop_val):
                            _close_session()
                            prev_start_reg_val = cur
                        else:
                            prev_start_reg_val = cur

                # If session is active, log all register pairs (unfiltered)
                if session_active:
                    all_pairs = ", ".join(f"{r}={v}" for r, v in sorted(registers.items()))
                    _write_session(f"[{wall}] [{src}->{dst}] FC={fc} {all_pairs}")

            elif fc == 5:
                coils = parse_fc5(pkt, m) or {}
                if session_active:
                    all_pairs = ", ".join(f"{a}={b}" for a, b in sorted(coils.items()))
                    _write_session(f"[{wall}] [{src}->{dst}] FC=5 {all_pairs}")

            elif fc == 15:
                coils = parse_fc15(pkt, m) or {}
                if session_active:
                    all_pairs = ", ".join(f"{a}={b}" for a, b in sorted(coils.items()))
                    _write_session(f"[{wall}] [{src}->{dst}] FC=15 {all_pairs}")

            # --- From here on: honor --fc for "watch" printing and trigger publishing ---
            watch_fc = (fc == args.fc)
            if not watch_fc:
                continue

            # -------- FC 3/4: Registers (watch printing + optional trigger publish) --------
            if fc in (3, 4):
                registers = registers_for_watch if registers_for_watch is not None else (parse_register_map(m, fc=fc) or {})

                # Update last-seen cache for ALL registers in this frame (for context payloads)
                for r, v in registers.items():
                    REG_LAST[r] = v  # ensures we can include latest 200/205 later

                # Edge-trigger: publish only when the trigger register's value changes
                trig_reg = args.trigger_change_reg
                if trig_reg is not None and trig_reg in registers:
                    cur_val = registers[trig_reg]
                    prev_pub = last_published_reg.get(trig_reg)
                    if prev_pub is None:
                        # First observation: initialize but do NOT publish
                        last_published_reg[trig_reg] = cur_val
                        if args.trace_triggers:
                            log_info(f"[trace] init change-reg {trig_reg}={cur_val}")
                    elif cur_val != prev_pub:
                        if not (args.trigger_once and trigger_fired):
                            context = {str(r): REG_LAST.get(r) for r in args.include_regs}
                            if args.trace_triggers:
                                ctx_str = ", ".join(f"{k}={v}" for k, v in sorted(context.items()))
                                log_info(f"[trace] CHANGE reg={trig_reg} {prev_pub}->{cur_val} ctx[{ctx_str}] -> PUBLISH")
                            payload = _build_payload(
                                args, wall, src, dst, fc,
                                trigger_reg=trig_reg, trigger_val=cur_val,
                                context_regs=context
                            )
                            mqtt_publish(payload)  # publishes dict as JSON to configured topic
                            last_published_reg[trig_reg] = cur_val
                            if args.trigger_once:
                                trigger_fired = True
                        elif args.trace_triggers:
                            log_info("[trace] trigger-once already fired; skipping publish")
                    elif args.trace_triggers:
                        log_info(f"[trace] no change reg={trig_reg} stays {cur_val}")

                # Console printing for watched set
                matched = {r: v for r, v in registers.items() if r in WATCH}
                if not matched:
                    continue
                if args.deltas_only:
                    changed = {r: v for r, v in matched.items() if REG_STATE.get(r) != v}
                    # Update state after computing changes
                    REG_STATE.update(matched)
                    if not changed:
                        continue
                    to_print = changed
                else:
                    to_print = matched
                    REG_STATE.update(matched)
                pairs = ", ".join(f"{r}={v}" for r, v in sorted(to_print.items()))
                log_info(f"[{wall}] [{src}->{dst}] FC={fc} {pairs}")

            # -------- FC 5: Write Single Coil (watch printing only) --------
            elif fc == 5:
                coils = parse_fc5(pkt, m) or {}
                matched = {a: b for a, b in coils.items() if a in WATCH}
                if not matched:
                    continue
                if args.deltas_only:
                    changed = {a: b for a, b in matched.items() if COIL_STATE.get(a) != b}
                    COIL_STATE.update(matched)
                    if not changed:
                        continue
                    to_print = changed
                else:
                    to_print = matched
                    COIL_STATE.update(matched)
                pairs = ", ".join(f"{a}={b}" for a, b in sorted(to_print.items()))
                log_info(f"[{wall}] [{src}->{dst}] FC=5 {pairs}")

            # -------- FC 15: Write Multiple Coils (watch printing only) --------
            elif fc == 15:
                coils = parse_fc15(pkt, m) or {}
                matched = {a: b for a, b in coils.items() if a in WATCH}
                if not matched:
                    continue
                if args.deltas_only:
                    changed = {a: b for a, b in matched.items() if COIL_STATE.get(a) != b}
                    COIL_STATE.update(matched)
                    if not changed:
                        continue
                    to_print = changed
                else:
                    to_print = matched
                    COIL_STATE.update(matched)
                pairs = ", ".join(f"{a}={b}" for a, b in sorted(to_print.items()))
                log_info(f"[{wall}] [{src}->{dst}] FC=15 {pairs}")

        return 0

    except pyshark.capture.capture.TSharkNotFoundException:
        log_err("tshark not found. Install Wireshark/TShark and ensure it's on PATH.")
        return 1
    except PermissionError:
        log_err("Permission denied. On Windows, run your shell as Administrator for live capture.")
        return 1
    finally:
        try:
            if cap:
                cap.close()
            _close_session()  # ensure file is closed
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
