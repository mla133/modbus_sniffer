from modbus.direction import normalize_func_code, get_packet_endpoints
from modbus.registers import parse_register_map, check_register_rules
from modbus.coils import parse_fc5, parse_fc15, check_coil_rules
from config import WATCH_REGISTERS, WATCH_COILS
from mqtt.client import mqtt_publish
from app_logging import log_err

def handle_packet(pkt):
    try:
        if not hasattr(pkt, "modbus"):
            return

        m = pkt.modbus
        fc = normalize_func_code(m)
        src, dst, _, _ = get_packet_endpoints(pkt)

        if fc in (3, 4):
            regs = parse_register_map(m, fc)
            matches = check_register_rules(regs, WATCH_REGISTERS)
            if matches:
                mqtt_publish({
                    "type": "register",
                    "ip": src,
                    "matches": matches
                })

        elif fc == 5:
            coils = parse_fc5(pkt, m)
            matches = check_coil_rules(coils, WATCH_COILS)
            if matches:
                mqtt_publish({
                    "type": "coil",
                    "ip": src,
                    "coils": coils
                })

        elif fc == 15:
            coils = parse_fc15(pkt, m)
            matches = check_coil_rules(coils, WATCH_COILS)
            if matches:
                mqtt_publish({
                    "type": "coil",
                    "ip": src,
                    "matches": matches
                })

    except Exception as e:
        log_err(f"Packet error: {e}")
