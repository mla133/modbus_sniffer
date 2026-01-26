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

## New usage for main.py
```
# via main.py (unified entry)
python main.py watch --pcap path\to\cap.pcapng --fc 3 --watch 100 200 201 --deltas-only
python main.py watch --iface "Ethernet 4" --fc 5 --watch 500 501 --deltas-only

# your thin script still works (see next step)
python scripts/modbus_watch.py --iface "Ethernet 4" --fc 15 --watch 500 501 502 --deltas-only
```

## Coverage reporting for unit tests
## Install coverage tooling
```
python -m pip install pytest-cov coverage
```

## Generate the coverage report in JSON
```
coverage run -m pytest -m unit
coverage json -o coverage.json
```

## Run the coverage Python script
```
python scripts/function_coverage_report.py
```

## Triggered packets and MQTT publishing
```
python src/cli/modbus_watch.py \
  --pcap tests/pcaps/sample.pcapng \
  --fc 3 \
  --watch 200 205 \
  --trigger-change-reg 100 \
  --include-regs 200 205 \
  --trace-triggers --echo-trigger
```
This script publishes a topic to the MQTT broker configured in _config.py_ that triggers when the register 100 changes.  It also publishes the most recent read of the watched registers (200, 205 in this example), and pushes that topic also.
