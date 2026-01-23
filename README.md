# modbus-sniffer

Modular Modbus TCP sniffer with PCAP replay and live capture.

## Quick start
```bash
python -m pip install -e .
pytest
```
## Usage 
```
usage: modbus_watch.py [-h] [--pcap PCAP] [--iface IFACE] [--fc FC]
                       [--src SRC] [--dst DST] [--watch WATCH [WATCH ...]]
                       [--deltas-only]

options:
  -h, --help            show this help message and exit

source:
  --pcap PCAP           PCAP/PCAPNG file to replay
  --iface IFACE         Live interface, e.g. "Ethernet 4"

filters:
  --fc FC               Modbus function code (default: 3)
  --src SRC             Only packets with this source IP
  --dst DST             Only packets with this destination IP

registers:
  --watch WATCH [WATCH ...]
                        Registers to print (default: 100 and 200220)
  --deltas-only         Print only when watched registers change value
```
