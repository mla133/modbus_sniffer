def get_modbus_pdu_bytes(packet):
    try:
        raw = getattr(packet.tcp, "payload", None)
        if raw:
            b = [int(x, 16) for x in str(raw).split(":")]
            return b[7:]
    except Exception:
        pass
    return None

def unpack_bits_from_bytes(bytes_list, quantity):
    bits = []
    for b in bytes_list:
        for i in range(8):
            bits.append((b >> i) & 1)
    return bits[:quantity]
