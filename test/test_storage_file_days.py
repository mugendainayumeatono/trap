import os
import json
import pytest
from datetime import datetime, timedelta
from trap.storage.file import FileStorage

def test_file_storage_rotation_by_days(tmp_path, monkeypatch):
    log_file = tmp_path / "test_days.log"
    # Rotate every 1 day, size is huge
    storage = FileStorage(str(log_file), max_size_mb=1000, max_days=1)
    
    # We don't call setup here because we'll manually create an old file
    # Write an entry from 2 days ago
    old_time = datetime.now() - timedelta(days=2)
    entry = {
        "timestamp": old_time.isoformat(),
        "sender_ip": "1.1.1.1",
        "content_hex": b"data".hex(),
        "decoded_content": "data",
        "protocol": "test"
    }
    with open(log_file, "w") as f:
        f.write(json.dumps(entry) + "\n")
        
    storage.setup()
    
    # Now record a new entry
    new_time = datetime.now()
    storage.record(new_time, "2.2.2.2", b"new_data", "new_data", "test2")
    
    # Check if rotated file exists
    files = os.listdir(tmp_path)
    # test_days.log (current) + test_days.log.<timestamp>
    assert len(files) >= 2
    assert any(f.startswith("test_days.log.") for f in files)
    assert os.path.exists(log_file) # new log file
    
    # verify the new log file has the new entry and the old is rotated
    with open(log_file, "r") as f:
        line = f.readline()
        data = json.loads(line)
        assert data["sender_ip"] == "2.2.2.2"

