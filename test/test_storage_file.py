import os
import json
import pytest
from datetime import datetime
from trap.storage.file import FileStorage

def test_file_storage_setup(tmp_path):
    log_file = tmp_path / "subdir" / "test.log"
    storage = FileStorage(str(log_file), 10)
    storage.setup()
    assert os.path.exists(tmp_path / "subdir")

def test_file_storage_record(tmp_path):
    log_file = tmp_path / "test.log"
    storage = FileStorage(str(log_file), 10)
    storage.setup()
    
    timestamp = datetime(2023, 1, 1, 12, 0, 0)
    storage.record(timestamp, "1.2.3.4", b"content", "decoded", "proto")
    
    assert os.path.exists(log_file)
    with open(log_file, "r") as f:
        line = f.readline()
        data = json.loads(line)
        assert data["sender_ip"] == "1.2.3.4"
        assert data["protocol"] == "proto"
        assert data["content_hex"] == b"content".hex()

def test_file_storage_rotation(tmp_path, monkeypatch):
    log_file = tmp_path / "test.log"
    # Small max size to trigger rotation
    storage = FileStorage(str(log_file), 0.000001) # very small
    storage.setup()
    
    # Write some data to make it exceed size
    with open(log_file, "w") as f:
        f.write("x" * 100)
    
    timestamp = datetime(2023, 1, 1, 12, 0, 0)
    storage.record(timestamp, "1.1.1.1", b"data", "data", "test")
    
    # Check if rotated file exists
    files = os.listdir(tmp_path)
    assert len(files) >= 2
    assert any(f.startswith("test.log.") for f in files)
    assert os.path.exists(log_file) # new log file
