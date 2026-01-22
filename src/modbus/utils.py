# src/modbus/utils.py
import struct
from .constants import ByteOrder, WordOrder

__all__ = ["intify", "decode_ieee_float32_from_regs", "ByteOrder", "WordOrder"]

def intify(x, default=None):
    """Convert decimal or hex-like strings to int; return default on failure/None."""
    if x is None:
        return default
    try:
        return int(str(x), 0)  # accepts '15', 15, '0xFF00', etc.
    except Exception:
        return default

def decode_ieee_float32_from_regs(reg_hi, reg_lo,
                                  byteorder=ByteOrder.BIG,
                                  wordorder=WordOrder.BIG):
    """
    Decode a float32 from two 16-bit Modbus registers with explicit control:

    wordorder:
      - BIG     -> (reg_hi, reg_lo)
      - LITTLE  -> (reg_lo, reg_hi)

    byteorder applies to the *byte order within each 16-bit register*:
      - BIG     -> 0xABCD -> [0xAB, 0xCD]
      - LITTLE  -> 0xABCD -> [0xCD, 0xAB]

    The final 4 bytes are then interpreted in network order (big-endian) as a float.
    """
    def reg_to_bytes(reg, per_reg_byteorder):
        hi = (reg >> 8) & 0xFF
        lo = reg & 0xFF
        return (hi, lo) if per_reg_byteorder == ByteOrder.BIG else (lo, hi)

    # Arrange the two registers by word order
    hi_reg, lo_reg = (reg_hi, reg_lo) if wordorder == WordOrder.BIG else (reg_lo, reg_hi)

    # Convert each 16-bit register to 2 bytes according to per-register byte order
    b0, b1 = reg_to_bytes(hi_reg, byteorder)
    b2, b3 = reg_to_bytes(lo_reg, byteorder)

    # Always interpret the resulting 4 bytes as big-endian float
    raw = bytes([b0, b1, b2, b3])
    return struct.unpack(">f", raw)[0]
