from abc import ABC, abstractmethod
from datetime import datetime

class Storage(ABC):
    @abstractmethod
    def record(self, timestamp: datetime, sender_ip: str, content: bytes, decoded_content: str, protocol: str):
        pass

    @abstractmethod
    def setup(self):
        pass
