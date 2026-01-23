# tests/test_replay_smoke.py
import re
import subprocess
import sys
from pathlib import Path

def test_replay_fc3_smoke():
    root = Path(__file__).resolve().parents[1]  # project root
    pcap = root / "pcaps" / "sample.pcapng"
    assert pcap.exists(), "Place a small sample PCAP at tests/pcaps/sample.pcapng"

    # Run the CLI for FC=3 with a small watch set
    cmd = [sys.executable, "main.py", "watch",
           "--pcap", str(pcap),
           "--fc", "3",
           "--watch", "100", "200", "201"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=20)

    # Basic assertions: exit code and at least one FC=3 line
    assert proc.returncode in (0, None), proc.stderr
    lines = [ln for ln in proc.stdout.splitlines() if "FC=3" in ln]
    assert len(lines) >= 1, f"No FC=3 output found.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"

    # (Optional) look for a timestamp and src/dst fields in one line
    pat = re.compile(r"\[\d{4}-\d{2}-\d{2}T.*Z\] \[.*->.*\] FC=3")
    assert any(pat.search(ln) for ln in lines), f"Output format unexpected: {lines[:3]}"
