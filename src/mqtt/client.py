import json
try:
    import paho.mqtt.client as mqtt
    MQTT_OK = True
except ImportError:
    MQTT_OK = False

from config import *
from app_logging import log_info, log_err

_client = None

def init_mqtt():
    global _client
    if not MQTT_OK:
        log_err("MQTT unavailable")
        return
    try:
        c = mqtt.Client(client_id=MQTT_CLIENT_ID, clean_session=True)
        c.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
        c.connect(MQTT_BROKER, MQTT_PORT, MQTT_KEEPALIVE)
        c.loop_start()
        _client = c
        log_info("MQTT connected")
    except Exception as e:
        log_err(str(e))

def mqtt_publish(payload):
    if _client:
        _client.publish(MQTT_TOPIC, json.dumps(payload), qos=1)
