import os
import json
import pytest
from datetime import datetime, timezone
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
    
    timestamp = datetime(2023, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    storage.record(timestamp, "1.2.3.4", b"content", "decoded", "proto")
    
    assert os.path.exists(log_file)
    with open(log_file, "r") as f:
        line = f.readline()
        data = json.loads(line)
        assert data["sender_ip"] == "1.2.3.4"
        assert data["protocol"] == "proto"
        assert data["content_hex"] == b"content".hex()

def test_no_file_initially(tmp_path):
    log_file = tmp_path / "test_no_file.log"
    storage = FileStorage(str(log_file), max_size_mb=1, max_days=1)
    storage.setup()
    storage.record(datetime.now(timezone.utc), "1.1.1.1", b"data", "data", "test")
    assert os.path.exists(log_file)

def test_max_bytes_rollover(tmp_path):
    log_file = tmp_path / "test_bytes.log"
    # Small max size to trigger rotation (~100 bytes)
    storage = FileStorage(str(log_file), max_size_mb=0.0001) 
    storage.setup()
    
    # 连续记录几条数据以触发轮转
    for _ in range(3):
        storage.record(datetime.now(timezone.utc), "1.1.1.1", b"data"*20, "data"*20, "test")
    
    # Check if rotated file exists
    files = os.listdir(tmp_path)
    # test_bytes.log (当前) + 至少一个轮转后的文件
    assert len(files) > 1
    assert any(f.startswith("test_bytes.log.") for f in files)
    assert os.path.exists(log_file)
