import pytest
import json
import os
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from trap.mcp_server import http_app, sse_app, fetch_logs_from_file, start_mcp_servers

# --- 单元测试：日志获取逻辑 ---

def test_fetch_logs_from_file(tmp_path):
    log_file = tmp_path / "honey.log"
    now = datetime.now(timezone.utc)
    
    # 准备测试数据
    log_entries = [
        {"timestamp": (now - timedelta(minutes=10)).isoformat(), "sender_ip": "1.1.1.1", "protocol": "http"},
        {"timestamp": now.isoformat(), "sender_ip": "2.2.2.2", "protocol": "tls"},
        {"timestamp": (now + timedelta(minutes=10)).isoformat(), "sender_ip": "3.3.3.3", "protocol": "unknown"},
    ]
    
    with open(log_file, "w") as f:
        for entry in log_entries:
            f.write(json.dumps(entry) + "\n")
            
    with patch("trap.mcp_server.LOG_FILE", str(log_file)):
        # 测试全量
        start_time = now - timedelta(minutes=15)
        result = fetch_logs_from_file(start_time, limit=10)
        assert len(result["logs"]) == 3
        assert result["total"] == 3
        
        # 测试分页 (limit=1, offset=1) -> 预期拿到中间那条 "2.2.2.2"
        # 注意逻辑是 reversed，所以 0: 3.3.3.3, 1: 2.2.2.2, 2: 1.1.1.1
        result = fetch_logs_from_file(start_time, limit=1, offset=1)
        assert len(result["logs"]) == 1
        assert result["logs"][0]["sender_ip"] == "2.2.2.2"
        assert result["has_more"] is True
        
        # 测试分页末尾
        result = fetch_logs_from_file(start_time, limit=1, offset=2)
        assert result["logs"][0]["sender_ip"] == "1.1.1.1"
        assert result["has_more"] is False

# --- 接口测试：HTTP REST API ---

client = TestClient(http_app)

def test_http_logs_endpoint(tmp_path):
    log_file = tmp_path / "honey.log"
    now = datetime.now(timezone.utc)
    entry = {"timestamp": now.isoformat(), "sender_ip": "127.0.0.1", "protocol": "test"}
    
    log_file.write_text(json.dumps(entry) + "\n")
    
    with patch("trap.mcp_server.LOG_FILE", str(log_file)):
        # 成功请求 (带分页参数)
        # 注意：需要对 ISO 时间进行 URL 编码，否则 +00:00 中的 + 会被解析为空格导致解析失败
        import urllib.parse
        encoded_ts = urllib.parse.quote(now.isoformat())
        response = client.get(f"/logs?start_time={encoded_ts}&limit=1&offset=0")
        assert response.status_code == 200
        data = response.json()
        assert len(data["logs"]) == 1
        assert data["logs"][0]["sender_ip"] == "127.0.0.1"
        
        # 错误日期格式 (应该返回 400 而不是 422)
        response = client.get("/logs?start_time=invalid-date")
        assert response.status_code == 400

# --- 接口测试：SSE (基础连通性) ---

def test_sse_endpoints():
    # 模拟 sse_transport 以避免复杂的长连接交互
    # 我们主要测试 POST /messages 接口，因为 GET /sse 是长连接，在同步测试环境下容易卡死
    with patch("trap.mcp_server.sse_transport.handle_post_message", new_callable=AsyncMock) as mock_handle:
        sse_client = TestClient(sse_app)
        response = sse_client.post("/messages", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
        assert response.status_code == 200
        assert mock_handle.called

# --- 启动逻辑测试 ---

@pytest.mark.asyncio
async def test_start_mcp_servers_config(monkeypatch):
    # 模拟 uvicorn.Server 以免真的启动端口
    with patch("uvicorn.Server.serve", new_callable=AsyncMock) as mock_serve:
        # 场景 1: 只开启 HTTP
        monkeypatch.setenv("MCP_HTTP_ENABLED", "true")
        monkeypatch.setenv("MCP_SSE_ENABLED", "false")
        monkeypatch.setenv("MCP_HTTP_PORT", "9000")
        
        tasks = await start_mcp_servers()
        assert len(tasks) == 1
        
        # 场景 2: 全部开启
        monkeypatch.setenv("MCP_SSE_ENABLED", "true")
        monkeypatch.setenv("MCP_SSE_PORT", "9001")
        
        tasks = await start_mcp_servers()
        assert len(tasks) == 2
        
        # 场景 3: 全部关闭
        monkeypatch.setenv("MCP_HTTP_ENABLED", "false")
        monkeypatch.setenv("MCP_SSE_ENABLED", "false")
        
        tasks = await start_mcp_servers()
        assert len(tasks) == 0

# --- 错误处理测试 ---

def test_fetch_logs_file_not_found():
    with patch("trap.mcp_server.LOG_FILE", "/non/existent/path"):
        result = fetch_logs_from_file(datetime.now())
        assert result["logs"] == []

def test_fetch_logs_corrupt_json(tmp_path):
    log_file = tmp_path / "corrupt.log"
    log_file.write_text("invalid json line\n{\"timestamp\": \"2026-01-01T00:00:00\", \"valid\": true}\n")
    
    with patch("trap.mcp_server.LOG_FILE", str(log_file)):
        result = fetch_logs_from_file(datetime(2025, 1, 1))
        assert len(result["logs"]) == 1
        assert result["logs"][0]["valid"] is True
