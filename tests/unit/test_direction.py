import types
from modbus.direction import normalize_func_code, get_packet_endpoints, modbus_transmit

def _pkt(ip_src="10.0.0.1", ip_dst="10.0.0.2", sport="1234", dport="502"):
    pkt = types.SimpleNamespace()
    pkt.ip = types.SimpleNamespace(src=ip_src, dst=ip_dst)
    pkt.tcp = types.SimpleNamespace(srcport=sport, dstport=dport)
    return pkt

def _modbus(func_code=5, **attrs):
    # Fake modbus layer; add arbitrary attributes to simulate presence/absence
    m = types.SimpleNamespace(func_code=func_code, **attrs)
    return m

def test_normalize_func_code_int_like():
    m = _modbus(func_code="5")
    assert normalize_func_code(m) == 5

def test_get_packet_endpoints_ipv4():
    pkt = _pkt()
    src, dst, sp, dp = get_packet_endpoints(pkt)
    assert (src, dst, sp, dp) == ("10.0.0.1", "10.0.0.2", "1234", "502")

def test_modbus_transmit_request_vs_response():
    # Request-like: has address/quantity but no values
    m_req = _modbus(func_code=15, ref_num=100, quantity=3)
    assert modbus_transmit(m_req) is False  # request

    # Response-like: has values but no ref/quantity fields
    m_resp = _modbus(func_code=15, bitval=types.SimpleNamespace(all_fields=[1,2]))
    assert modbus_transmit(m_resp) is True  # response

    # Ambiguous when both present
    m_amb = _modbus(func_code=15, quantity=1, bitval=types.SimpleNamespace(all_fields=[1]))
    assert modbus_transmit(m_amb) is None
