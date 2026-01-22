from .utils import intify

def normalize_func_code(m):
    return intify(getattr(m, "func_code", None), default=-1)

def modbus_transmit(m):
    has_vals = hasattr(m, "regval_uint16") or hasattr(m, "bitval")
    has_req = hasattr(m, "ref_num") or hasattr(m, "quantity")
    if has_vals and not has_req:
        return True
    if has_req and not has_vals:
        return False
    return None

def get_packet_endpoints(pkt):
    src = dst = sport = dport = None
    if hasattr(pkt, "ip"):
        src = pkt.ip.src
        dst = pkt.ip.dst
    if hasattr(pkt, "tcp"):
        sport = pkt.tcp.srcport
        dport = pkt.tcp.dstport
    return src, dst, sport, dport
