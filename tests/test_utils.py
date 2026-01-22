import math
from modbus.utils import decode_ieee_float32_from_regs
from modbus.constants import ByteOrder, WordOrder

def _assert_is_one(v): assert math.isclose(v, 1.0, rel_tol=1e-6)

def test_float32_big_big_1_0():
    # 1.0f = 0x3F 80 00 00
    reg_hi, reg_lo = 0x3F80, 0x0000
    _assert_is_one(decode_ieee_float32_from_regs(reg_hi, reg_lo,
                      byteorder=ByteOrder.BIG, wordorder=WordOrder.BIG))

def test_float32_big_little_wordorder_1_0():
    # Word swap only: 0x0000 0x3F80
    reg_hi, reg_lo = 0x0000, 0x3F80
    _assert_is_one(decode_ieee_float32_from_regs(reg_hi, reg_lo,
                      byteorder=ByteOrder.BIG, wordorder=WordOrder.LITTLE))

def test_float32_little_big_per_reg_1_0():
    # Per-register little-endian, big word order:
    # hi reg 0x803F -> bytes [0x3F,0x80], lo reg 0x0000 -> [0x00,0x00]
    reg_hi, reg_lo = 0x803F, 0x0000
    _assert_is_one(decode_ieee_float32_from_regs(reg_hi, reg_lo,
                      byteorder=ByteOrder.LITTLE, wordorder=WordOrder.BIG))

def test_float32_little_little_both_swapped_1_0():
    # Word swap + per-register little: lo=0x803F, hi=0x0000
    reg_hi, reg_lo = 0x0000, 0x803F
    _assert_is_one(decode_ieee_float32_from_regs(reg_hi, reg_lo,
                      byteorder=ByteOrder.LITTLE, wordorder=WordOrder.LITTLE))
