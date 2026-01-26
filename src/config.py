import socket

NIC_ADDRESS = "Ethernet 4"

# MQTT
MQTT_BROKER = "192.168.181.78"
MQTT_PORT = 1883
MQTT_TOPIC = "modbus/triggers"
MQTT_CLIENT_ID = f"modbus-sniffer-{socket.gethostname()}"
MQTT_USERNAME = "debian"
MQTT_PASSWORD = "temppwd"
MQTT_KEEPALIVE = 60

# Pulse box
PULSE_BOX_IP = "10.0.0.71"
PULSE_BOX_STATE_REG = 100
PULSE_BOX_MM1_REG = 200
PULSE_BOX_MM2_REG = 201
PULSE_BOX_MUT1_REG = 202

WATCH_REGISTERS = {
    PULSE_BOX_STATE_REG: {"eq": 3},
    PULSE_BOX_STATE_REG: {"eq": 4},
}

WATCH_COILS = {}
