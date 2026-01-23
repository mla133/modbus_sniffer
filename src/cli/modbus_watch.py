# src/cli/modbus_watch.py
import sys
import signal
import argparse
from datetime import timezone
import pyshark

from modbus.direction import normalize_func_code, get_packet_endpoints
from modbus.registers import parse_register_map
from modbus.coils import parse_fc5, parse_fc15
from app_logging import log_err, log_info, _ts    # rename if you used a different module name


def _build_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="modbus-watch",
        description="Watch Modbus packets (PCAP or live) and print selected values."
    )
    srcdst = ap.add_argument_group("source")
    srcdst.add_argument("--pcap", help="PCAP/PCAPNG file to replay")
    srcdst.add_argument("--iface", help='Live interface name, e.g. "Ethernet 4"')

    filt = ap.add_argument_group("filters")
    filt.add_argument("--fc", type=int, default=3, choices=[3, 5, 15],
                      help="Modbus function code to watch (3, 5, or 15). Default: 3")
    filt.add_argument("--src", help="Only packets with this source IP")
    filt.add_argument("--dst", help="Only packets with this destination IP")

    watch = ap.add_argument_group("watch set")
    watch.add_argument(
        "--watch", nargs="+", type=int,
        default=[100] + list(range(200, 221)),
        help="Registers/Coils to print. Used for FC=3 (registers) and FC=5/15 (coils). "
             "Default: 100 and 200..220"
    )

    ap.add_argument("--deltas-only", action="store_true",
                    help="Print only when watched values change from their last seen value")

    return ap.parse_args(argv)


def main(argv=None):
    args = _build_args(argv)

    if not (args.pcap or args.iface):
        log_err("Choose one: --pcap <file> or --iface <name>")
        return 2

    # Wireshark display filter (post-capture filter)
    display_df = "modbus && tcp.port == 502"
    if args.src:
        display_df += f" && ip.src == {args.src}"
    if args.dst:
        display_df += f" && ip.dst == {args.dst}"

    cap = None
    try:
        if args.pcap:
            cap = pyshark.FileCapture(
                args.pcap,
                display_filter=display_df,
                keep_packets=False
            )
            iterator = cap
            log_info(f"[+] Replaying PCAP: {args.pcap}")
        else:
            # LiveCapture: do NOT pass keep_packets
            bpf = "tcp port 502"
            cap = pyshark.LiveCapture(
                interface=args.iface,
                display_filter=display_df,
                bpf_filter=bpf
            )
            iterator = cap.sniff_continuously()
            log_info(f"[+] Live on {args.iface} (Ctrl-C to stop)")

        WATCH = set(args.watch)

        # state caches for deltas
        REG_STATE = {}   # register -> last_value (for FC=3)
        COIL_STATE = {}  # coil_addr -> last_bit  (for FC=5/15)

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

            if fc == 3:
                registers = parse_register_map(m, fc=3)  # {reg: value}
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
                log_info(f"[{wall}] [{src}->{dst}] FC=3  {pairs}")

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
                log_info(f"[{wall}] [{src}->{dst}] FC=5  {pairs}")

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
