# tests/unit/test_modbus_watch_cli.py
import types
from datetime import datetime, timezone as dt_tz
import builtins
import sys

import pytest

# We import the module under test after monkeypatching to ensure our stubs are used
MODULE_PATH = "cli.modbus_watch"


class FakePkt:
    """A tiny packet object with the attributes modbus_watch.py expects."""
    def __init__(self, has_modbus=True, ts=None):
        self.sniff_time = ts or datetime(2026, 1, 23, 16, 24, 41, 137000, tzinfo=dt_tz.utc)
        if has_modbus:
            self.modbus = types.SimpleNamespace()
        # else: no 'modbus' attr


def _install_fake_pyshark(monkeypatch, packets):
    """Make FileCapture return an object iterable over our packets, and LiveCapture unused."""
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


def _install_fake_modbus_helpers(monkeypatch, fc_value=3, registers_by_pkt=None, coils_by_pkt=None):
    """
    fc_value: function code the normalizer returns for all packets
    registers_by_pkt: dict mapping packet -> {reg: value}
    coils_by_pkt: dict mapping packet -> {addr: bit}
    """
    if registers_by_pkt is None:
        registers_by_pkt = {}
    if coils_by_pkt is None:
        coils_by_pkt = {}

    def normalize_func_code(_m):
        return fc_value

    def get_packet_endpoints(_pkt):
        return ("10.1.2.3", "10.2.3.4", None, None)

    def parse_register_map(m, fc):
        # Find current packet by looking up a sentinel attached in tests
        pkt = getattr(m, "_pkt_ref", None)
        return registers_by_pkt.get(pkt, {})

    def parse_fc5(pkt, m):
        return coils_by_pkt.get(pkt, {})

    def parse_fc15(pkt, m):
        return coils_by_pkt.get(pkt, {})

    # Patch into module namespaces used by modbus_watch.py
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
        log_info=catcher.log_info, log_err=catcher.log_err, _ts=lambda: "T"
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


def test_args_defaults(monkeypatch):
    # Light import to access _build_args
    catcher = LogCatcher()
    _install_fake_logging(monkeypatch, catcher)
    _install_fake_pyshark(monkeypatch, [])
    _install_fake_modbus_helpers(monkeypatch)

    mod = _import_under_test(monkeypatch)
    args = mod._build_args(["--pcap", "dummy.pcapng"])
    # defaults: fc=3, watch = [100] + 200..210
    assert args.fc == 3
    assert args.watch[0] == 100 and args.watch[1:] == list(range(200, 211))  # default set


def test_replay_fc3_basic_prints(monkeypatch, tmp_path):
    catcher = LogCatcher()
    _install_fake_logging(monkeypatch, catcher)

    # One packet with reg hits watch: 100=5
    p1 = FakePkt()
    packets = [p1]
    _attach_pkt_refs(packets)

    _install_fake_pyshark(monkeypatch, packets)
    _install_fake_modbus_helpers(monkeypatch, fc_value=3, registers_by_pkt={p1: {100: 5, 123: 9}})

    mod = _import_under_test(monkeypatch)
    rc = mod.main(["--pcap", "dummy.pcapng", "--fc", "3", "--watch", "100"])
    assert rc == 0
    # Expect a line showing FC=3 and 100=5
    assert any("FC=3" in line and "100=5" in line for line in catcher.infos)


def test_replay_fc3_filters_by_watch(monkeypatch):
    catcher = LogCatcher()
    _install_fake_logging(monkeypatch, catcher)

    p1 = FakePkt()
    packets = [p1]
    _attach_pkt_refs(packets)

    _install_fake_pyshark(monkeypatch, packets)
    # Packet contains reg 300=7, but watch set is 100 only -> no output
    _install_fake_modbus_helpers(monkeypatch, fc_value=3, registers_by_pkt={p1: {300: 7}})

    mod = _import_under_test(monkeypatch)
    rc = mod.main(["--pcap", "dummy.pcapng", "--fc", "3", "--watch", "100"])
    assert rc == 0
    # No info lines expected (no watched registers matched)
    assert not any("FC=3" in line for line in catcher.infos)


def test_replay_fc3_deltas_only(monkeypatch):
    catcher = LogCatcher()
    _install_fake_logging(monkeypatch, catcher)

    # Three packets for the same watched reg {100}: 5 -> 5 -> 6
    p1, p2, p3 = FakePkt(), FakePkt(), FakePkt()
    packets = [p1, p2, p3]
    _attach_pkt_refs(packets)

    _install_fake_pyshark(monkeypatch, packets)
    _install_fake_modbus_helpers(monkeypatch, fc_value=3, registers_by_pkt={
        p1: {100: 5},
        p2: {100: 5},
        p3: {100: 6},
    })

    mod = _import_under_test(monkeypatch)
    rc = mod.main(["--pcap", "dummy.pcapng", "--fc", "3", "--watch", "100", "--deltas-only"])
    assert rc == 0

    # Expect first print (5) AND third print (6), but not the second (unchanged)
    printed_5 = any("100=5" in line for line in catcher.infos)
    printed_6 = any("100=6" in line for line in catcher.infos)
    # Ensure we didn't log three identical prints; just 2 lines for deltas-only case
    # (There may be other log lines; we count lines that contain the watched reg)
    watched_lines = [line for line in catcher.infos if "FC=3" in line and "100=" in line]
    assert printed_5 and printed_6 and len(watched_lines) == 2
