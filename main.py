# main.py
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(prog="modbus-sniffer", description="Modbus toolbelt")
    sub = parser.add_subparsers(dest="cmd", required=True)

    watch = sub.add_parser("watch", help="PCAP or live watch (FC 3/5/15, optional --deltas-only)")
    watch.set_defaults(handler="watch")

    # Parse only the first-level command; pass the rest through
    args, rest = parser.parse_known_args()

    if args.cmd == "watch":
        from cli.modbus_watch import main as watch_main
        # Forward leftover args to the watch CLI so we don't duplicate flags
        return watch_main(rest)

    # Fallback (shouldn't hit due to required=True)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
