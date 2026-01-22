import types
from modbus.coils import parse_fc5, parse_fc15

def _fake_tcp_payload(hex_bytes):
    # Build a colon-separated string like "00:01:00:00:00:06:01:05:01:F4:FF:00"
    return ":".join(f"{b:02X}" for b in hex_bytes)

def _pkt_with_pdu(pdu_bytes):
    """
    Builds a fake packet whose tcp.payload is MBAP(7 bytes) + PDU.
    MBAP = [0,1,  0,0,  0,6,  unit=1] -> 7 bytes
    """
    mbap = [0x00,0x01, 0x00,0x00, 0x00,0x06, 0x01]
    full = mbap + pdu_bytes
    tcp = types.SimpleNamespace(payload=_fake_tcp_payload(full))
    return types.SimpleNamespace(tcp=tcp)

def _modbus_layer(**attrs):
    return types.SimpleNamespace(**attrs)

def test_parse_fc5_from_pdu_on():
    # FC=5, address=0x01F4 (500), value=0xFF00 -> ON
    pdu = [0x05, 0x01, 0xF4, 0xFF, 0x00]
    pkt = _pkt_with_pdu(pdu)
    m = _modbus_layer()  # no fields; force PDU fallback
    coils = parse_fc5(pkt, m)
    assert coils == {500: 1}

def test_parse_fc5_from_pdu_off():
    # FC=5, value=0x0000 -> OFF
    pdu = [0x05, 0x01, 0xF4, 0x00, 0x00]
    pkt = _pkt_with_pdu(pdu)
    m = _modbus_layer()
    coils = parse_fc5(pkt, m)
    assert coils == {500: 0}

def test_parse_fc15_from_pdu_three_bits():
    # FC=15, start=500 (0x01F4), qty=3, bytecount=1, values=0b101 (LSB-first)
    # bits -> [1,0,1] addressing 500,501,502
    pdu = [0x0F, 0x01, 0xF4, 0x00, 0x03, 0x01, 0b00000101]
    pkt = _pkt_with_pdu(pdu)
    m = _modbus_layer()
    coils = parse_fc15(pkt, m)
    assert coils == {500: 1, 501: 0, 502: 1}
