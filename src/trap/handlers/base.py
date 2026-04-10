from abc import ABC, abstractmethod

class ProtocolHandler(ABC):
    @abstractmethod
    def identify(self, data: bytes) -> bool:
        pass

    @abstractmethod
    def handle(self, data: bytes) -> tuple[str, str, bytes]:
        """
        Returns: (protocol_name, decoded_content, response_bytes)
        """
        pass
