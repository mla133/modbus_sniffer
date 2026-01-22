import pyshark
from config import NIC_ADDRESS
from capture.base import PacketSource

class LivePacketSource(PacketSource):
    def packets(self):
        cap = pyshark.LiveCapture(
            interface=NIC_ADDRESS,
            display_filter='modbus && tcp.port == 502'
        )
        yield from cap.sniff_continuously()
