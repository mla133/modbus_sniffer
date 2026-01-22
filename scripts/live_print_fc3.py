# scripts/live_print_fc3.py
import sys
import signal
from datetime import timezone
import pyshark

from modbus.direction import normalize_func_code, get_packet_endpoints
from modbus.registers import parse_register_map
from app_logging import log_err, log_info, _ts    # rename if you used a different module name

WATCH_SET = {100} | set(range(200, 221))  # {100, 200..220}

def main():
    if len(sys.argv) < 2:
        log_info("Usage: python scripts/live_print_fc3.py <interface>")
        log_info('Example: python scripts/live_print_fc3.py "Ethernet 4"')
        sys.exit(1)

    interface = sys.argv[1]

    cap = pyshark.LiveCapture(
        interface=interface,
        display_filter="modbus && tcp.port == 502"
    )

    log_info(f"[+] Listening on {interface} (Ctrl-C to stop)")

    # Graceful Ctrl‑C
    def stop_capture(sig, frame):
        log_info("\n[!] Stopping capture...")
        cap.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop_capture)

    for pkt in cap.sniff_continuously():
        if not hasattr(pkt, "modbus"):
            continue

        m = pkt.modbus
        fc = normalize_func_code(m)

        if fc != 3:
            continue

        registers = parse_register_map(m, fc=3)
        matched = {r: v for r, v in registers.items() if r in WATCH_SET}
        if not matched:
            continue

        src, dst, _, _ = get_packet_endpoints(pkt)

        wall = pkt.sniff_time.astimezone(timezone.utc) \
                             .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        rel = float(pkt.frame_info.time_relative)

        log_info(
            f"[{wall} | +{rel:7.3f}s] "
            f"[{src}->{dst}] FC=3 {dict(sorted(matched.items()))}"
        )

if __name__ == "__main__":
    main()
