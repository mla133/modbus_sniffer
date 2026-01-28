# tests/unit/test_mqtt_version.py
"""
Verify that our MQTT client uses paho-mqtt Callback API VERSION2 and that
the v2 callbacks accept both 4-arg and 5-arg forms without raising.

This test:
 - inserts "<repo>/src" on sys.path so we can import "mqtt.client" from src layout
 - monkeypatches paho.mqtt.client.Client to capture the first positional arg
   (the callback_api_version) and to no-op loop_start/connect/etc.
 - calls init_mqtt(), asserts VERSION2 was passed
 - manually invokes on_disconnect with both 4 and 5 arguments; it should not raise
"""

import importlib
import sys
from pathlib import Path

import paho.mqtt.client as pm


def test_mqtt_uses_version2_and_callbacks_are_resilient(monkeypatch):
    # Make "<repo>/src" importable so "import mqtt.client" works
    repo_root = Path(__file__).resolve().parents[2]  # tests/unit -> tests -> <repo>
    src_dir = repo_root / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

    seen = {}

    class FakeClient:
        def __init__(self, *a, **k):
            # Capture the first positional arg (callback_api_version)
            seen["v"] = a[0] if a else None
            # Attributes that init_mqtt() sets
            self.on_connect = None
            self.on_disconnect = None

        # Methods called by init_mqtt(); no-op them
        def reconnect_delay_set(self, *args, **kwargs): pass
        def username_pw_set(self, *args, **kwargs): pass
        def connect(self, *args, **kwargs): pass
        def loop_start(self, *args, **kwargs): pass

    # Replace the real Client with our stub that captures the first arg
    monkeypatch.setattr(pm, "Client", lambda *a, **k: FakeClient(*a, **k))

    # Import (and reload to ensure monkeypatch is in effect)
    mod = importlib.import_module("mqtt.client")
    importlib.reload(mod)

    # Initialize MQTT
    mod.init_mqtt()

    # Assert we selected VERSION2 at instantiation time
    assert seen["v"] == pm.CallbackAPIVersion.VERSION2

    # Callbacks should be set on the client instance created in init_mqtt()
    assert mod._client is not None
    assert callable(mod._client.on_disconnect)

    # Explicitly invoke on_disconnect with both 4-arg and 5-arg forms to ensure resilience
    # 4-arg: (client, userdata, reason_code, properties)
    mod._client.on_disconnect(mod._client, None, 0, None)
    # 5-arg: (client, userdata, flags, reason_code, properties)
    mod._client.on_disconnect(mod._client, None, None, 0, None)
