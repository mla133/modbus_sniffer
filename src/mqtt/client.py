# src/mqtt/client.py
import json

try:
    import paho.mqtt.client as mqtt
    from paho.mqtt.client import CallbackAPIVersion
    MQTT_OK = True
except ImportError:
    MQTT_OK = False

from config import *  # existing pattern retained; consider namespaced imports later
from app_logging import log_info, log_err

_client = None
_connected = False


def init_mqtt():
    """Initialize MQTT client using paho-mqtt v2 Callback API VERSION2."""
    global _client, _connected
    if not MQTT_OK:
        log_err("MQTT unavailable")
        return
    try:
        # Select v2 callback API to remove deprecation warnings and align with paho 2.x
        # Docs: migrations & Client constructor.
        c = mqtt.Client(
            CallbackAPIVersion.VERSION2,
            client_id=MQTT_CLIENT_ID,
            clean_session=True,  # OK for MQTT v3.1.1; for v5 use clean_start in connect()
        )

        # Resilience: reconnect backoff
        c.reconnect_delay_set(min_delay=1, max_delay=30)

        # Authentication (optional) and TLS (optional)
        if MQTT_USERNAME:
            c.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        # If your broker uses TLS (e.g., port 8883), uncomment:
        # if MQTT_PORT == 8883:
        #     c.tls_set()

        # ---- v2 callback signatures (robust to 4-arg vs 5-arg variants) ----
        def _on_connect(client, userdata, *args):
            """
            Tolerate both:
            - (client, userdata, flags, reason_code, properties)  [5 args]
            - (client, userdata, reason_code, properties)          [4 args]
            """
            global _connected
            flags = None
            reason_code = None
            properties = None
            if len(args) == 4:
                flags, reason_code, properties = args[0], args[1], args[2]  # extra arg guard
            elif len(args) == 3:
                flags, reason_code, properties = args[0], args[1], args[2]
            elif len(args) == 2:
                reason_code, properties = args[0], args[1]
            else:
                reason_code = args[0] if args else 0
            _connected = (reason_code == 0)
            if _connected:
                log_info("MQTT connected")
            else:
                log_err(f"MQTT connect failed: {reason_code}")

        def _on_disconnect(client, userdata, *args):
            """
            Tolerate both:
            - (client, userdata, flags, reason_code, properties)  [5 args]
            - (client, userdata, reason_code, properties)          [4 args]
            """
            global _connected
            _connected = False
            if len(args) >= 2:
                reason_code = args[1]
            elif len(args) >= 1:
                reason_code = args[0]
            else:
                reason_code = None
            log_err(f"MQTT disconnected: {reason_code}")

        c.on_connect = _on_connect
        c.on_disconnect = _on_disconnect

        c.connect(MQTT_BROKER, MQTT_PORT, MQTT_KEEPALIVE)
        c.loop_start()
        _client = c
    except Exception as e:
        log_err(f"MQTT init error: {e}")


def mqtt_publish(payload):
    """Publish JSON payload at QoS 1. Returns True on success, False otherwise."""
    if not _client:
        log_err("MQTT publish failed: client not initialized")
        return False
    try:
        result = _client.publish(MQTT_TOPIC, json.dumps(payload), qos=1)
        return getattr(result, "rc", None) == mqtt.MQTT_ERR_SUCCESS
    except Exception as e:
        log_err(f"MQTT publish error: {e}")
        return False
