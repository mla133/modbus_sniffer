# scripts/replay_print_fc3.py
import sys
import pyshark

from modbus.direction import normalize_func_code, get_packet_endpoints
from modbus.registers import parse_register_map
from app_logging import log_err, log_info, _ts    # rename if you used a different module name

WATCH_SET = {100} | set(range(200, 211))  # {100, 200..210}

def main():
    if len(sys.argv) < 2:
        log_info(f"Usage: python scripts/replay_print_fc3.py <pcap|pcapng> [display_filter]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    # Let users optionally pass an extra display_filter (e.g., "ip.addr==10.0.0.71")
    extra_df = sys.argv[2] if len(sys.argv) > 2 else None

    # Build a Wireshark display filter: Modbus over TCP(502) + optional extra
    df = "modbus && tcp.port == 502"
    if extra_df:
        df = f"({df}) && ({extra_df})"

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter=df,
        keep_packets=False  # saves memory
    )

    try:
        for pkt in cap:
            if not hasattr(pkt, "modbus"):
                continue
            m = pkt.modbus
            fc = normalize_func_code(m)
            if fc != 3:
                continue

            src, dst, sp, dp = get_packet_endpoints(pkt)
            registers = parse_register_map(m, fc=3)  # {reg: value}

            # Filter down to 100 and 200..210
            to_print = {r: v for r, v in registers.items() if r in WATCH_SET}
            if not to_print:
                continue

            # Pretty print one line per packet
            # Example format:
            # [timestamp] [10.0.0.10 -> 10.0.0.71] FC=3  {100: 3, 200: 1234, 201: 65535}

            ts = pkt.sniff_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            log_info(f"[{ts}] [{src} -> {dst}] FC=3  {dict(sorted(to_print.items()))}")

    except Exception as e:
        log_err(f"Replay error: {e}")
    finally:
        cap.close()


if __name__ == "__main__":
    main()
