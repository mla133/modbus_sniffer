from .field_finder import get_all_field_ints

def parse_register_map(m, fc):
    regnums = get_all_field_ints(m, "regnum16")
    regvals = get_all_field_ints(m, "regval_uint16")
    return dict(zip(regnums, regvals))

def check_register_rules(registers, rules):
    matches = []
    for reg, rule in rules.items():
        if reg not in registers:
            continue
        v = registers[reg]
        if "eq" in rule and v == rule["eq"]:
            matches.append({"register": reg, "value": v})
    return matches
