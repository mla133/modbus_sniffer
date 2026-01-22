from abc import ABC, abstractmethod

class PacketSource(ABC):
    @abstractmethod
    def packets(self):
        """Yield pyshark packets"""
        pass
