import os
import json
import time
import pytest
from datetime import datetime, timedelta, timezone
from trap.storage.file import FileStorage, CombinedRotatingHandler
from trap.mcp_server import fetch_logs_from_file

def test_fetch_logs_from_multiple_files(tmp_path):
    log_file = tmp_path / "honey.log"
    
    # 1. 创建当前的日志文件
    now = datetime.now(timezone.utc)
    current_entry = {"timestamp": now.isoformat(), "sender_ip": "current", "protocol": "test"}
    log_file.write_text(json.dumps(current_entry) + "\n")
    
    # 2. 创建一个“已轮转”的日志文件
    old_time = now - timedelta(days=2)
    rotated_file = tmp_path / "honey.log.20260101"
    rotated_entry = {"timestamp": old_time.isoformat(), "sender_ip": "rotated", "protocol": "test"}
    rotated_file.write_text(json.dumps(rotated_entry) + "\n")
    
    # 3. 模拟 LOG_FILE 环境变量
    import trap.mcp_server
    old_log_file = trap.mcp_server.LOG_FILE
    trap.mcp_server.LOG_FILE = str(log_file)
    
    try:
        # 搜索过去 3 天的日志
        start_time = now - timedelta(days=3)
        results = fetch_logs_from_file(start_time)
        
        # 验证是否找到了两个文件中的日志
        ips = [r["sender_ip"] for r in results]
        assert "current" in ips
        assert "rotated" in ips
        assert len(results) == 2
    finally:
        trap.mcp_server.LOG_FILE = old_log_file

def test_rotation_no_cleanup(tmp_path):
    log_file = tmp_path / "test_no_cleanup.log"
    # 设置 max_days 为 1 天
    storage = FileStorage(str(log_file), max_size_mb=10, max_days=1)
    storage.setup()
    
    # 手动创建一个非常旧的轮转文件
    old_rotated = tmp_path / "test_no_cleanup.log.old"
    old_rotated.write_text("old data")
    
    # 触发轮转
    handler = None
    for h in storage.logger.handlers:
        if isinstance(h, CombinedRotatingHandler):
            handler = h
            break
    
    assert handler is not None
    # 强制触发轮转
    handler.doRollover()
    
    # 验证旧文件仍然存在（没有自动清理）
    assert os.path.exists(old_rotated)
    
    # 验证产生了新的轮转文件
    files = os.listdir(tmp_path)
    assert any(f.startswith("test_no_cleanup.log.") and f != "test_no_cleanup.log.old" for f in files)

def test_rollover_at_calculation_on_restart(tmp_path):
    log_file = tmp_path / "test_restart.log"
    
    # 1. 模拟一个 2 天前创建的文件
    old_time = datetime.now(timezone.utc) - timedelta(days=2)
    entry = {"timestamp": old_time.isoformat(), "sender_ip": "1.1.1.1", "protocol": "test"}
    log_file.write_text(json.dumps(entry) + "\n")
    
    # 2. 启动存储，设置 max_days 为 3
    # 预期 rolloverAt 应该是 old_time + 3 days
    storage = FileStorage(str(log_file), max_size_mb=10, max_days=3)
    storage.setup()
    
    handler = None
    for h in storage.logger.handlers:
        if isinstance(h, CombinedRotatingHandler):
            handler = h
            break
            
    expected_rollover = old_time.timestamp() + (3 * 24 * 3600)
    # 允许一点误差
    assert abs(handler.rolloverAt - expected_rollover) < 1.0
