import os
import json
import threading
from datetime import datetime
from .base import Storage

class FileStorage(Storage):
    def __init__(self, file_path: str, max_size_mb: float):
        self.file_path = file_path
        self.max_size = max_size_mb * 1024 * 1024
        self.lock = threading.Lock()

    def setup(self):
        directory = os.path.dirname(self.file_path)
        if directory:
            os.makedirs(directory, exist_ok=True)

    def _rotate_if_needed(self):
        # Assumes lock is already held
        try:
            if os.path.exists(self.file_path) and os.path.getsize(self.file_path) >= self.max_size:
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S_%f")
                os.rename(self.file_path, f"{self.file_path}.{timestamp}")
        except OSError as e:
            print(f"Warning: Failed to rotate log file: {e}")

    def record(self, timestamp: datetime, sender_ip: str, content: bytes, decoded_content: str, protocol: str):
        with self.lock:
            self._rotate_if_needed()
            entry = {
                "timestamp": timestamp.isoformat(),
                "sender_ip": sender_ip,
                "content_hex": content.hex(),
                "decoded_content": decoded_content,
                "protocol": protocol
            }
            with open(self.file_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
