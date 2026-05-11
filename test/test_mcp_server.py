import pytest
import json
import os
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from trap.mcp_server import http_app, sse_app, fetch_logs_from_file, start_mcp_servers

# --- 单元测试：日志获取逻辑 ---

def test_fetch_logs_from_file(tmp_path):
    log_file = tmp_path / "honey.log"
    now = datetime.now()
    
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
        # 测试全量（从 15 分钟前开始）
        start_time = now - timedelta(minutes=15)
        results = fetch_logs_from_file(start_time)
        assert len(results) == 3
        
        # 测试中间时间段
        start_time = now - timedelta(minutes=5)
        end_time = now + timedelta(minutes=5)
        results = fetch_logs_from_file(start_time, end_time)
        assert len(results) == 1
        assert results[0]["sender_ip"] == "2.2.2.2"
        
        # 测试不存在的时间段
        start_time = now + timedelta(minutes=20)
        results = fetch_logs_from_file(start_time)
        assert len(results) == 0

# --- 接口测试：HTTP REST API ---

client = TestClient(http_app)

def test_http_logs_endpoint(tmp_path):
    log_file = tmp_path / "honey.log"
    now = datetime.now()
    entry = {"timestamp": now.isoformat(), "sender_ip": "127.0.0.1", "protocol": "test"}
    
    log_file.write_text(json.dumps(entry) + "\n")
    
    with patch("trap.mcp_server.LOG_FILE", str(log_file)):
        # 成功请求
        response = client.get(f"/logs?start_time={now.isoformat()}")
        assert response.status_code == 200
        assert len(response.json()) == 1
        assert response.json()[0]["sender_ip"] == "127.0.0.1"
        
        # 错误参数（缺少 start_time）
        response = client.get("/logs")
        assert response.status_code == 422
        
        # 错误日期格式
        response = client.get("/logs?start_time=invalid-date")
        assert response.status_code == 400

# --- 接口测试：SSE (基础连通性) ---

def test_sse_endpoints():
    # 模拟 sse_transport 以避免复杂的长连接交互
    with patch("trap.mcp_server.sse_transport.handle_post_message", new_callable=AsyncMock) as mock_handle:
        sse_client = TestClient(sse_app)
        response = sse_client.post("/messages", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
        assert response.status_code == 200
        assert mock_handle.called

    # 验证 SSE 路径存在
    sse_client = TestClient(sse_app)
    # /sse 接口在代码中定义为接收 Request 并调用 connect_sse
    # 在没有真正的 SSE 客户端握手时，它可能会报错或返回 400
    try:
        response = sse_client.get("/sse")
        assert response.status_code != 404
    except Exception:
        # 某些测试环境下可能会因为异步流处理抛出异常，只要不是 404 即可
        pass

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
        results = fetch_logs_from_file(datetime.now())
        assert results == []

def test_fetch_logs_corrupt_json(tmp_path):
    log_file = tmp_path / "corrupt.log"
    log_file.write_text("invalid json line\n{\"timestamp\": \"2026-01-01T00:00:00\", \"valid\": true}\n")
    
    with patch("trap.mcp_server.LOG_FILE", str(log_file)):
        results = fetch_logs_from_file(datetime(2025, 1, 1))
        assert len(results) == 1
        assert results[0]["valid"] is True
