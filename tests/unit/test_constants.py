from modbus.constants import ByteOrder, WordOrder


def test_byte_order():
    assert ByteOrder.BIG.value == "BIG"
    assert ByteOrder.LITTLE.value == "LITTLE"


def test_word_order():
    assert WordOrder.BIG.value == "BIG"
    assert WordOrder.LITTLE.value == "LITTLE"


def test_enum_types():
    assert ByteOrder.BIG is not WordOrder.BIG
