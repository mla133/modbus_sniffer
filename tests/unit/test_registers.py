import types
from modbus.registers import parse_register_map, check_register_rules

class _FieldList:
    def __init__(self, values):
        # mimic PyShark: each entry has .showname_value
        self.all_fields = [types.SimpleNamespace(showname_value=v) for v in values]

class _FakeModbusLayer:
    def __init__(self, regnums, regvals):
        # provide get_field("regnum16") & get_field("regval_uint16")
        self._map = {
            "regnum16": _FieldList(regnums),
            "regval_uint16": _FieldList(regvals),
        }
    def get_field(self, name):
        return self._map[name]

def test_parse_register_map_basic():
    m = _FakeModbusLayer(regnums=[100, 101], regvals=[3, 7])
    registers = parse_register_map(m, fc=3)
    assert registers == {100: 3, 101: 7}

def test_check_register_rules_eq_match():
    regs = {100: 3, 101: 7}
    rules = {100: {"eq": 3}, 101: {"eq": 8}}
    matches = check_register_rules(regs, rules)
    assert matches == [{"register": 100, "value": 3}]
