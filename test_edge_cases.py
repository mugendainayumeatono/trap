import os
import json
import time
from datetime import datetime
from trap.storage.file import FileStorage

def test_no_file():
    storage = FileStorage("test_no_file.log", max_size_mb=1, max_days=1)
    storage.setup()
    storage.record(datetime.now(), "1.1.1.1", b"data", "data", "test")
    assert os.path.exists("test_no_file.log")
    
    # Clean up
    for f in os.listdir('.'):
        if f.startswith('test_no_file.log'):
            os.remove(f)
            
def test_max_bytes_rollover():
    storage = FileStorage("test_bytes.log", max_size_mb=0.0001, max_days=1) # ~100 bytes
    storage.setup()
    storage.record(datetime.now(), "1.1.1.1", b"data"*20, "data"*20, "test")
    storage.record(datetime.now(), "1.1.1.1", b"data"*20, "data"*20, "test")
    storage.record(datetime.now(), "1.1.1.1", b"data"*20, "data"*20, "test")
    
    files = [f for f in os.listdir('.') if f.startswith('test_bytes.log')]
    assert len(files) > 1, f"Expected rollover, found {files}"
    
    # Clean up
    for f in files:
        os.remove(f)

if __name__ == '__main__':
    test_no_file()
    test_max_bytes_rollover()
    print("All tests passed.")
