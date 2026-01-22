import json
import datetime
import sys

def _ts():
    return datetime.datetime.utcnow().isoformat()

def log_info(msg):
    sys.stdout.write(f"[INFO] {msg}\n")
    sys.stdout.flush()

def log_err(msg):
    sys.stdout.write(f"[ERROR] {msg}\n")
    sys.stdout.flush()

def log_time(msg):
    sys.stdout.write(f"[TIME] {_ts()}{msg}\n")
    sys.stdout.flush()

def log_mqtt(payload):
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()
