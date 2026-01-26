# src/cli/modbus_watch_change.py
import sys
import signal
import argparse
from datetime import timezone
import pyshark

from modbus.direction import normalize_func_code, get_packet_endpoints
from modbus.registers import parse_register_map
from modbus.coils import parse_fc5, parse_fc15
from app_logging import log_err, log_info, _ts

# Project MQTT module (uses config.py)
# If your module is at project root as client.py, change the import to:
#   from client import init_mqtt, mqtt_publish
from mqtt.client import init_mqtt, mqtt_publish


def _build_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="modbus-watch-change",
        description=(
            "Watch Modbus packets (PCAP or live). Publish to MQTT only when the trigger "
            "register's value CHANGES, and include the latest values of selected context registers."
        ),
    )

    # Source selection
    srcdst = ap.add_argument_group("source")
    srcdst.add_argument("--pcap", help="PCAP/PCAPNG file to replay")
    srcdst.add_argument("--iface", help='Live interface name, e.g. "Ethernet 4"')

    # Filters
    filt = ap.add_argument_group("filters")
    filt.add_argument(
        "--fc", type=int, default=3, choices=[3, 4, 5, 15],
        help="Modbus function code to watch (3, 4, 5, or 15). Default: 3"
    )
    filt.add_argument("--src", help="Only packets with this source IP")
    filt.add_argument("--dst", help="Only packets with this destination IP")

    # Watch set (console printing only)
    watch = ap.add_argument_group("watch set")
    watch.add_argument(
        "--watch", nargs="+", type=int,
        default=[100] + list(range(200, 211)),
        help=("Registers/Coils to print. Used for FC=3/4 (registers) and FC=5/15 (coils). "
              "Default: 100 and 200..210")
    )
    ap.add_argument(
        "--deltas-only", action="store_true",
        help="Print only when watched values change from their last seen value"
    )

    # Edge-triggered publishing (no comparison; publish on any value change)
    trig = ap.add_argument_group("edge trigger (publish on change)")
    trig.add_argument(
        "--trigger-change-reg", type=int, required=True,
        help="Register address to publish on any value change (FC=3/4)"
    )
    trig.add_argument(
        "--trigger-once", action="store_true",
        help="Publish only the first time the trigger condition is met (first change)"
    )

    # Context to include when the trigger fires (e.g., 200 and 205)
    ap.add_argument(
        "--include-regs", nargs="+", type=int, default=[200, 205],
        help="Register addresses whose latest values will be included in the MQTT payload when the trigger fires. Default: 200 205"
    )

    # Diagnostics / payload
    ap.add_argument(
        "--payload-format", choices=["json", "text"], default="json",
        help="Publish JSON dict (default) or simple text payload"
    )
    ap.add_argument(
        "--trace-triggers", action="store_true",
        help="Log why triggers did or didn't fire (diagnostic)"
    )
    ap.add_argument(
        "--echo-trigger", action="store_true",
        help="Also include the trigger register in console output (adds it to --watch)"
    )

    return ap.parse_args(argv)


def _build_payload(args, ts, src, dst, fc, trigger_reg, trigger_val, context_regs):
    """
    Return payload in the structure expected by client.mqtt_publish(payload):
      - if args.payload_format == 'json': dict (client.py json.dumps it)
      - else: str
    """
    if args.payload_format == "text":
        ctx = ", ".join(f"{k}={v}" for k, v in sorted(context_regs.items()))
        return f"{ts} {src}->{dst} fc={fc} reg={trigger_reg} value={trigger_val} ctx[{ctx}]"

    # JSON dict (your MQTT client will json.dumps it)
    return {
        "ts": ts, "src": src, "dst": dst, "fc": fc,
        "reg": trigger_reg, "value": trigger_val,
        "context": context_regs
    }


def main(argv=None):
    args = _build_args(argv)

    if not (args.pcap or args.iface):
        log_err("Choose one: --pcap <file> or --iface <name>")
        return 2

    # Initialize shared MQTT client (reads config.py)
    init_mqtt()

    trigger_fired = False  # for --trigger-once
    last_published_reg = {}  # reg -> last value we actually published (edge trigger)

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
        REG_STATE = {}   # used for console delta printing of WATCHed registers
        REG_LAST  = {}   # last seen value for ANY register (for context payloads)
        COIL_STATE = {}  # unchanged for coils

        def _stop(sig, frame):
            log_info("\n[!] Stopping...")
            try:
                if cap:
                    cap.close()
            finally:
                sys.exit(0)

        signal.signal(signal.SIGINT, _stop)

        for pkt in iterator:
            if not hasattr(pkt, "modbus"):
                continue

            m = pkt.modbus
            fc = normalize_func_code(m)
            if fc != args.fc:
                continue

            src, dst, _, _ = get_packet_endpoints(pkt)
            wall = pkt.sniff_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

            # ----------------- FC 3/4: Registers -----------------
            if fc in (3, 4):
                registers = parse_register_map(m, fc=fc) or {}  # {reg: value}

                # Update last-seen cache for ALL registers in this frame
                for r, v in registers.items():
                    REG_LAST[r] = v

                # Edge-trigger: publish only when the trigger register's value changes
                trig_reg = args.trigger_change_reg
                if trig_reg in registers:
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
                            mqtt_publish(payload)
                            last_published_reg[trig_reg] = cur_val
                            if args.trigger_once:
                                trigger_fired = True
                        elif args.trace_triggers:
                            log_info("[trace] trigger-once already fired; skipping publish")
                    elif args.trace_triggers:
                        log_info(f"[trace] no change reg={trig_reg} stays {cur_val}")

                # Console printing for watched set (unchanged)
                matched = {r: v for r, v in registers.items() if r in WATCH}
                if not matched:
                    continue

                if args.deltas_only:
                    changed = {r: v for r, v in matched.items() if REG_STATE.get(r) != v}
                    for r, v in matched.items():
                        REG_STATE[r] = v
                    if not changed:
                        continue
                    to_print = changed
                else:
                    to_print = matched
                    for r, v in matched.items():
                        REG_STATE[r] = v

                pairs = ", ".join(f"{r}={v}" for r, v in sorted(to_print.items()))
                log_info(f"[{wall}] [{src}->{dst}] FC={fc} {pairs}")

            # ----------------- FC 5: Write Single Coil -----------------
            elif fc == 5:
                coils = parse_fc5(pkt, m) or {}
                matched = {a: b for a, b in coils.items() if a in WATCH}
                if not matched:
                    continue

                if args.deltas_only:
                    changed = {a: b for a, b in matched.items() if COIL_STATE.get(a) != b}
                    for a, b in matched.items():
                        COIL_STATE[a] = b
                    if not changed:
                        continue
                    to_print = changed
                else:
                    to_print = matched
                    for a, b in matched.items():
                        COIL_STATE[a] = b

                pairs = ", ".join(f"{a}={b}" for a, b in sorted(to_print.items()))
                log_info(f"[{wall}] [{src}->{dst}] FC=5 {pairs}")

            # ----------------- FC 15: Write Multiple Coils -----------------
            elif fc == 15:
                coils = parse_fc15(pkt, m) or {}
                matched = {a: b for a, b in coils.items() if a in WATCH}
                if not matched:
                    continue

                if args.deltas_only:
                    changed = {a: b for a, b in matched.items() if COIL_STATE.get(a) != b}
                    for a, b in matched.items():
                        COIL_STATE[a] = b
                    if not changed:
                        continue
                    to_print = changed
                else:
                    to_print = matched
                    for a, b in matched.items():
                        COIL_STATE[a] = b

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
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
