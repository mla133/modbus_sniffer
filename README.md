# modbus-sniffer

Modular Modbus TCP sniffer with PCAP replay and live capture.

## Quick start
```bash
python -m pip install -e .
pytest
```

## Usage (live capture)
```
python scripts/live_print_fc3.py "Ethernet 4"
```

## Usage (PCAP file)
```
python scripts/replay_print_fc3.py path/to/file.pcapng
```
