import time
import pyshark
from capture.base import PacketSource

class PcapPacketSource(PacketSource):
    def __init__(self, pcap_path, realtime=False, speed=1.0):
        """
        pcap_path : path to .pcap or .pcapng
        realtime  : replay packets with original timing
        speed     : timing multiplier (2.0 = 2x faster)
        """
        self.pcap_path = pcap_path
        self.realtime = realtime
        self.speed = speed

    def packets(self):
        cap = pyshark.FileCapture(
            self.pcap_path,
            display_filter='modbus && tcp.port == 502',
            keep_packets=False
        )

        prev_ts = None

        for pkt in cap:
            if self.realtime and hasattr(pkt, 'sniff_time'):
                if prev_ts:
                    delta = (pkt.sniff_time - prev_ts).total_seconds()
                    time.sleep(delta / self.speed)
                prev_ts = pkt.sniff_time

            yield pkt
