# src/modbus/coils.py

from .field_finder import find_field
from .pdu import get_modbus_pdu_bytes, unpack_bits_from_bytes

__all__ = ["parse_fc5", "parse_fc15", "check_coil_rules"]


def parse_fc5(packet, m):
    """
    FC=5 (Write Single Coil)
    Returns {address: bit}, where bit is 1 for 0xFF00 and 0 for 0x0000.
    Tries dissector fields first, then falls back to raw PDU parsing.
    """
    # Try to resolve via fields
    addr, _ = find_field(
        m,
        ["ref_num", "reference_number", "coil_address", "address"],
        as_int=True,
    )
    outv, _ = find_field(
        m,
        ["outval", "output_value", "coil_status", "value"],
        as_int=True,
    )
    if addr is not None and outv is not None:
        bit = 1 if outv == 0xFF00 else 0
        return {addr: bit}

    # Fallback: raw PDU
    pdu = get_modbus_pdu_bytes(packet)
    if not pdu or len(pdu) < 5 or pdu[0] != 0x05:
        return {}
    addr = (pdu[1] << 8) | pdu[2]
    outv = (pdu[3] << 8) | pdu[4]
    bit = 1 if outv == 0xFF00 else 0
    return {addr: bit}


def parse_fc15(packet, m):
    """
    FC=15 (Write Multiple Coils)
    Returns flat dict {address: bit}.
    Uses field names when possible; otherwise falls back to raw PDU.
    """
    # Try to read via fields
    addr, _ = find_field(
        m,
        ["ref_num", "reference_number", "address", "starting_address"],
        as_int=True,
    )
    qty, _ = find_field(
        m,
        ["quantity", "ref_cnt", "quantity_of_outputs", "quantity_of_coils"],
        as_int=True,
    )

    pdu = get_modbus_pdu_bytes(packet)
    if not pdu or len(pdu) < 6 or pdu[0] != 0x0F:
        return {}

    if addr is None or qty is None:
        # Decode from PDU when fields are missing
        addr = (pdu[1] << 8) | pdu[2]
        qty = (pdu[3] << 8) | pdu[4]
        bytecnt = pdu[5]
        bytes_list = pdu[6 : 6 + bytecnt]
    else:
        # We know addr/qty; still extract the packed bytes from PDU
        bytecnt = pdu[5] if len(pdu) > 5 else 0
        bytes_list = pdu[6 : 6 + bytecnt] if bytecnt else pdu[6:]

    if qty is None or not bytes_list:
        return {}

    bits = unpack_bits_from_bytes(bytes_list, qty)
    return {addr + i: bits[i] for i in range(len(bits))}


def check_coil_rules(coils, rules):
    """
    Compare parsed coils to watch rules.
    Returns list of match dicts: [{"coil": addr, "value": bit}, ...]
    """
    return [
        {"coil": addr, "value": val}
        for addr, val in coils.items()
        if addr in rules and rules[addr] == val
    ]
