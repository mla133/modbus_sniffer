# modbus-sniffer

Modular Modbus TCP sniffer with PCAP replay and live capture.

## Quick start

```bash
python -m pip install -e .
pytest
```

## Usage

```bash
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

```bash
# via main.py (unified entry)
python main.py watch --pcap path\to\cap.pcapng --fc 3 --watch 100 200 201 --deltas-only
python main.py watch --iface "Ethernet 4" --fc 5 --watch 500 501 --deltas-only

# your thin script still works (see next step)
python scripts/modbus_watch.py --iface "Ethernet 4" --fc 15 --watch 500 501 502 --deltas-only
```

## Coverage reporting for unit tests

## Install coverage tooling

```bash
python -m pip install pytest-cov coverage
```

## Generate the coverage report in JSON

```bash
coverage run -m pytest -m unit
coverage json -o coverage.json
```

## Run the coverage Python script

```bash
python scripts/function_coverage_report.py
```

## Triggered packets and MQTT publishing

```bash
python src/cli/modbus_watch.py \
  --pcap tests/pcaps/sample.pcapng \
  --fc 3 \
  --watch 200 205 \
  --trigger-change-reg 100 \
  --include-regs 200 205 \
  --trace-triggers --echo-trigger
```

This script publishes a topic to the MQTT broker configured in _config.py_ that triggers when the register 100 changes.  It also publishes the most recent read of the watched registers (200, 205 in this example), and pushes that topic also.

### Session logging (start on `100 → 3`, stop on `100 → 4`)

You can ask the sniffer to **start a new log file** whenever a specific register hits a value,
then **record all Modbus traffic** until the register moves to another value:

```bash
python main.py watch \
  --pcap tests/pcaps/sample.pcapng \
  --fc 3 \
  --session-log \
  --log-dir ./logs
```

## Testing EXE Builds

1. **Basic PCAP Replay (FC=3)**
This verifies your executable can:
- read a PCAP/PCAPNG file
- parse Modbus registers via PyShark
- print watched addresses

```bash
modbus-sniffer.exe watch --pcap "C:\captures\test.pcapng" --fc 3 --watch 100 200 205
```

Expected: Lines like:

```bash
[2026-01-27T14:45:02.123Z] [10.1.2.3->10.2.3.4] FC=3 100=5, 200=42, 205=1
```

2. **PCAP Replay with --deltas-only**
   This tests your delta‑tracking logic and ensures registers are remembered and compared across packets.

```bash
modbus-sniffer.exe watch
    --pcap "C:\captures\changes_only.pcapng"
    --fc 3
    --watch 100
    --deltas-onlyShow more lines
```

Expected: Only prints when register 100 changes value. (e.g. if packets contain 5 → 5 → 6), you should see only:

```bash
FC=3 100=5
FC=3 100=6
```

3. **Session Logging (start on 100=3, stop on 100=4)**
This verifies:
- session‑file creation
- session‑log capture of all FC 3/4/5/15
- correct start/stop edge detection

```bash
modbus-sniffer.exe watch
    --pcap "C:\captures\session_trace.pcapng"
    --fc 3
    --session-log
    --log-dir "C:\logs\modbus"
```

After running:
- A file like *C:\logs\modbus\2026-01-27_15-44-55.txt* should exist.
- File should contain mixed entries, e.g.:

```bash
[...Z] FC=3 100=3, 200=5
[...Z] FC=5 10=1, 11=0
[...Z] FC=3 100=4
```

4. **Custom Session Start/Stop Values**
If you want to test non‑default behavior:

```bash
modbus-sniffer.exe watch
  --pcap "session_alt.pcapng"
  --fc 3
  --session-log
  --session-start-reg 150
  --session-start-val 7
  --session-stop-val 9
  --log-dir "C:\logs\alt"
```
5. **MQTT Trigger Mode (FC 3 change → MQTT publish)**
This tests:

- your MQTT v2 callbacks
- stable trigger edge detection
- inclusion of context registers

```bash
modbus-sniffer.exe watch 
    --pcap "trigger_demo.pcapng" 
    --fc 3 
    --trigger-change-reg 100
    --include-regs 200 205
    --payload-format json
    --trace-triggers
    --echo-trigger
```
Expected logs:
```bash
[trace] init change-reg 100=5
[trace] CHANGE reg=100 5->7 ctx[200=44, 205=1] -> PUBLISH
```
If your MQTT broker is reachable, messages should appear on the target topic.
