from abc import ABC, abstractmethod

class ProtocolHandler(ABC):
    @abstractmethod
    def identify(self, data: bytes) -> bool:
        pass

    @abstractmethod
    def handle(self, data: bytes, session_id: str = "") -> tuple[str, str, bytes]:
        """
        Returns: (protocol_name, decoded_content, response_bytes)
        """
        pass

    def cleanup(self, session_id: str = "") -> None:
        """
        Called when a connection is closed or times out.
        Allows stateful handlers to clean up resources.
        """
        pass
