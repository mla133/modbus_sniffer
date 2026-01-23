# scripts/modbus_watch.py
import sys
import signal
from datetime import timezone
import pyshark

from modbus.direction import normalize_func_code, get_packet_endpoints
from modbus.registers import parse_register_map
from app_logging import log_err, log_info, _ts    # rename if you used a different module name

def main():
    import argparse
    ap = argparse.ArgumentParser()
    srcdst = ap.add_argument_group("source")
    srcdst.add_argument("--pcap", help="PCAP/PCAPNG file to replay")
    srcdst.add_argument("--iface", help='Live interface, e.g. "Ethernet 4"')

    filt = ap.add_argument_group("filters")
    filt.add_argument("--fc", type=int, default=3, help="Modbus function code (default: 3)")
    filt.add_argument("--src", help="Only packets with this source IP")
    filt.add_argument("--dst", help="Only packets with this destination IP")

    watch = ap.add_argument_group("registers")
    watch.add_argument("--watch", nargs="+", type=int, default=[100] + list(range(200, 221)),
                       help="Registers to print (default: 100 and 200–220)")
    watch.add_argument("--deltas-only", action="store_true", 
                       help="Print only when watched registers change value")

    args = ap.parse_args()

    if not (args.pcap or args.iface):
        log_err("Choose one: --pcap <file> or --iface <name>", file=sys.stderr)
        sys.exit(2)

    # Wireshark display filter (applied by tshark after capture)
    display_df = "modbus && tcp.port == 502"
    if args.src:
        display_df += f" && ip.src == {args.src}"
    if args.dst:
        display_df += f" && ip.dst == {args.dst}"

    cap = None
    try:
        if args.pcap:
            # FileCapture supports keep_packets
            cap = pyshark.FileCapture(args.pcap, display_filter=display_df, keep_packets=False)
            iterator = cap
            log_info(f"[+] Replaying PCAP: {args.pcap}")
        else:
            # LiveCapture does NOT accept keep_packets;
            # prefer a BPF capture filter for efficiency
            # (This runs in the capture engine, keeping memory usage low.)
            bpf = "tcp port 502"
            # You can embed host filters at BPF level too for extra speed:
            # if args.src and args.dst: bpf = f"tcp port 502 and src host {args.src} and dst host {args.dst}"
            cap = pyshark.LiveCapture(
                interface=args.iface,
                display_filter=display_df,
                bpf_filter=bpf
            )
            iterator = cap.sniff_continuously()
            print(f"[+] Live on {args.iface} (Ctrl-C to stop)")

        WATCH = set(args.watch)

        def _stop(sig, frame):
            log_info("\n[!] Stopping...")
            try:
                if cap:
                    cap.close()
            finally:
                sys.exit(0)

        signal.signal(signal.SIGINT, _stop)

        STATE = {}  # register -> last_value

        for pkt in iterator:
            if not hasattr(pkt, "modbus"):
                continue
            m = pkt.modbus
            if normalize_func_code(m) != args.fc:
                continue

            regs = parse_register_map(m, fc=args.fc)
            matched = {r: v for r, v in regs.items() if r in WATCH}
#            if not matched:
#                continue
#
#            src, dst, _, _ = get_packet_endpoints(pkt)
#            wall = pkt.sniff_time.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
#            pairs = ", ".join(f"{r}={v}" for r, v in sorted(matched.items()))
#            print(f"[{wall}] [{src}->{dst}] FC={args.fc}  {pairs}")


            # Filter out non-changing registers if --deltas-only is active
            if args.deltas_only:
                changed = {r: v for r, v in matched.items() if STATE.get(r) != v}
                # Update the state for any matched registers
                for r, v in matched.items():
                    STATE[r] = v
                if not changed:
                    continue
                to_print = changed
            else:
                to_print = matched
                # Update state too (for future transitions)
                for r, v in matched.items():
                    STATE[r] = v
            
            src, dst, _, _ = get_packet_endpoints(pkt)
            wall = pkt.sniff_time.astimezone(timezone.utc) \
                                .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            pairs = ", ".join(f"{r}={v}" for r, v in sorted(to_print.items()))
            log_info(f"[{wall}] [{src}->{dst}] FC={args.fc}  {pairs}")

    except pyshark.capture.capture.TSharkNotFoundException:
        log_err("tshark not found. Install Wireshark/TShark and ensure it's on PATH.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        log_err("Permission denied. On Windows, run your shell as Administrator for live capture.", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            if cap:
                cap.close()
        except Exception:
            pass

if __name__ == "__main__":
    main()
