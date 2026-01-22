from .utils import intify

FIELD_MAP = {
    "address": None,
    "output_value": None,
    "quantity": None,
    "byte_count": None,
}

def dump_layer_fields(layer):
    out = {}
    for fname in getattr(layer, "field_names", []):
        try:
            f = layer.get_field(fname)
            out[fname] = getattr(f, "showname_value", str(f))
        except Exception:
            out[fname] = None
    return out

def find_field(layer, candidates, as_int=False, record_key=None):
    for name in candidates:
        val = getattr(layer, name, None)
        if val is not None:
            return (intify(val) if as_int else val, name)

        try:
            fld = layer.get_field(name)
            val = getattr(fld, "showname_value", fld)
            if record_key and FIELD_MAP[record_key] is None:
                FIELD_MAP[record_key] = name
            return (intify(val) if as_int else val, name)
        except Exception:
            pass

    for fname, sval in dump_layer_fields(layer).items():
        for hint in candidates:
            if hint.replace("_", "") in fname.replace("_", ""):
                return (intify(sval) if as_int else sval, fname)

    return None, None

def get_all_field_ints(layer, fieldname):
    try:
        fld = layer.get_field(fieldname)
        return [intify(f.showname_value) for f in fld.all_fields]
    except Exception:
        return []
