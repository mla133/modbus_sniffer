import sys
from pathlib import Path

from mqtt.client import init_mqtt
from capture.live_capture import LivePacketSource
from capture.pcap_replay import PcapPacketSource
from pipeline.packet_handler import handle_packet
from app_logging import log_info

sys.path.insert(0, str(Path(__file__).parent))

def main():
    init_mqtt()

    if len(sys.argv) > 1:
        pcap = sys.argv[1]
        log_info(f"Replaying PCAP: {pcap}")
        source = PcapPacketSource(
            pcap_path=pcap,
            realtime=True,
            speed=1.0
        )
    else:
        log_info("Starting live capture")
        source = LivePacketSource()

    for pkt in source.packets():
        handle_packet(pkt)

if __name__ == "__main__":
    main()
