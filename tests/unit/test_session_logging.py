# tests/unit/test_session_logging.py
import re
import types
from datetime import datetime, timezone as dt_tz
from pathlib import Path
import sys

# --- Make "<repo>/src" importable so we can import "cli.modbus_watch"
REPO_ROOT = Path(__file__).resolve().parents[2]  # tests/unit -> tests -> <repo>
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
MODULE_PATH = "cli.modbus_watch"


class FakePkt:
    """Packet object with attributes modbus_watch.py expects."""
    def __init__(self, fc, ts=None):
        self.sniff_time = ts or datetime(2026, 1, 23, 16, 24, 41, 137000, tzinfo=dt_tz.utc)
        self.modbus = types.SimpleNamespace()
        # We'll let normalize_func_code read this
        setattr(self.modbus, "fc", fc)


def _install_fake_pyshark(monkeypatch, packets):
    """Make FileCapture return an iterable over our packets; LiveCapture unused."""
    class FakeFileCapture:
        def __init__(self, *_args, **_kwargs):
            self._closed = False
        def __iter__(self):
            return iter(packets)
        def close(self):
            self._closed = True
    class FakeLiveCapture(FakeFileCapture):
        def sniff_continuously(self):
            return iter(packets)
    fake_pyshark = types.SimpleNamespace(FileCapture=FakeFileCapture, LiveCapture=FakeLiveCapture)
    monkeypatch.setitem(sys.modules, "pyshark", fake_pyshark)
    return fake_pyshark


def _install_fake_modbus_helpers(monkeypatch, registers_by_pkt=None, coils_by_pkt=None):
    if registers_by_pkt is None:
        registers_by_pkt = {}
    if coils_by_pkt is None:
        coils_by_pkt = {}

    def normalize_func_code(m):
        return getattr(m, "fc", 3)

    def get_packet_endpoints(_pkt):
        return ("10.1.2.3", "10.2.3.4", None, None)

    def parse_register_map(m, fc):
        # lookup by object identity on a back-reference we attach below
        pkt = getattr(m, "_pkt_ref", None)
        return registers_by_pkt.get(pkt, {})

    def parse_fc5(pkt, m):
        return coils_by_pkt.get(pkt, {})

    def parse_fc15(pkt, m):
        return coils_by_pkt.get(pkt, {})

    # Publish into module namespaces used by modbus_watch.py
    monkeypatch.setitem(sys.modules, "modbus.direction", types.SimpleNamespace(
        normalize_func_code=normalize_func_code, get_packet_endpoints=get_packet_endpoints
    ))
    monkeypatch.setitem(sys.modules, "modbus.registers", types.SimpleNamespace(
        parse_register_map=parse_register_map
    ))
    monkeypatch.setitem(sys.modules, "modbus.coils", types.SimpleNamespace(
        parse_fc5=parse_fc5, parse_fc15=parse_fc15
    ))


class LogCatcher:
    def __init__(self):
        self.infos = []
        self.errs = []
    def log_info(self, msg):
        self.infos.append(msg)
    def log_err(self, msg):
        self.errs.append(msg)


def _install_fake_logging(monkeypatch, catcher: LogCatcher):
    monkeypatch.setitem(sys.modules, "app_logging", types.SimpleNamespace(
        log_info=catcher.log_info, log_err=catcher.log_err
    ))


def _import_under_test(monkeypatch):
    # Ensure a clean import (module reload), in case prior tests imported it
    if MODULE_PATH in sys.modules:
        del sys.modules[MODULE_PATH]
    mod = __import__(MODULE_PATH, fromlist=["*"])
    return mod


def _attach_pkt_refs(packets):
    """Attach back-references used by our fake parse_* to look up packet-specific data."""
    for p in packets:
        if hasattr(p, "modbus"):
            setattr(p.modbus, "_pkt_ref", p)


def test_session_logging_start_log_all_then_stop(monkeypatch, tmp_path):
    catcher = LogCatcher()
    _install_fake_logging(monkeypatch, catcher)

    # Build a 3-packet "trace":
    # p1: FC=3, registers include start-reg 100->3 (opens session)
    # p2: FC=5, coils during active session (should be logged)
    # p3: FC=3, registers include stop-reg 100->4 (closes session)
    p1 = FakePkt(fc=3)
    p2 = FakePkt(fc=5)
    p3 = FakePkt(fc=3)
    packets = [p1, p2, p3]
    _attach_pkt_refs(packets)

    regs_by_pkt = {
        p1: {100: 3, 200: 5},
        p3: {100: 4},
    }
    coils_by_pkt = {
        p2: {10: 1, 11: 0},
    }

    _install_fake_pyshark(monkeypatch, packets)
    _install_fake_modbus_helpers(monkeypatch, registers_by_pkt=regs_by_pkt, coils_by_pkt=coils_by_pkt)

    # Import after monkeypatching
    mod = _import_under_test(monkeypatch)

    # Run CLI with --pcap (FileCapture path), --fc 3, and session logging enabled to tmp_path
    rc = mod.main([
        "--pcap", "dummy.pcapng",
        "--fc", "3",
        "--session-log",
        "--log-dir", str(tmp_path),
    ])
    assert rc == 0

    # Exactly one timestamped .txt file should be created
    files = list(tmp_path.glob("*.txt"))
    assert len(files) == 1
    fn = files[0].name
    assert re.match(r"\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}\.txt$", fn)

    # File should contain both FC=3 (registers) and FC=5 (coils) lines
    text = files[0].read_text(encoding="utf-8")
    assert "FC=3" in text, f"expected FC=3 lines in session log; got:\n{text}"
    assert "FC=5" in text, f"expected FC=5 lines in session log; got:\n{text}"
