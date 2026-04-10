import pytest
import asyncio
import os
from unittest.mock import MagicMock, patch, AsyncMock
from datetime import datetime
from trap.main import Honeypot

@pytest.fixture
def mock_storage():
    with patch("trap.main.FileStorage") as mock:
        yield mock

@pytest.fixture(autouse=True)
def setup_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "test.log"))
    monkeypatch.setenv("STORAGE_TYPE", "file")

def test_honeypot_init_file(mock_storage, monkeypatch, tmp_path):
    monkeypatch.setenv("STORAGE_TYPE", "file")
    log_file = str(tmp_path / "init_test.log")
    monkeypatch.setenv("LOG_FILE", log_file)
    hp = Honeypot()
    assert hp.storage is not None
    mock_storage.assert_called_once()

@patch("trap.main.MySQLStorage")
def test_honeypot_init_mysql(mock_mysql, monkeypatch):
    monkeypatch.setenv("STORAGE_TYPE", "mysql")
    monkeypatch.setenv("MYSQL_HOST", "localhost")
    hp = Honeypot()
    assert hp.storage is not None
    mock_mysql.assert_called_once()

@pytest.mark.asyncio
async def test_handle_connection():
    # Mock reader and writer
    reader = AsyncMock()
    # Use side_effect to return data once then EOF, avoiding infinite loop
    reader.read.side_effect = [b"GET / HTTP/1.1\r\n\r\n", b""]
    
    writer = MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    
    hp = Honeypot()
    hp.storage = MagicMock()
    
    await hp.handle_connection(reader, writer)
    
    # Check if storage recorded the event
    assert hp.storage.record.called
    args = hp.storage.record.call_args[0]
    # args: (timestamp, sender_ip, data, decoded_content, protocol_name)
    assert args[1] == "127.0.0.1"
    assert b"GET /" in args[2]
    assert args[4] == "http"
    
    # Check if response was sent
    assert writer.write.called
    assert b"HTTP/1.1 200 OK" in writer.write.call_args[0][0]

@pytest.mark.asyncio
async def test_handle_connection_exception():
    # Mock reader that raises an exception
    reader = AsyncMock()
    reader.read.side_effect = Exception("Read error")
    
    writer = MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    writer.wait_closed = AsyncMock()
    
    hp = Honeypot()
    hp.storage = MagicMock()
    
    # This should not raise exception but print it
    with patch("builtins.print") as mock_print:
        await hp.handle_connection(reader, writer)
        assert any("Error handling connection from 127.0.0.1: Read error" in str(arg) for arg in mock_print.call_args_list)
    
    assert writer.close.called

@pytest.mark.asyncio
async def test_handle_connection_no_data():
    reader = AsyncMock()
    reader.read.return_value = b""
    
    writer = MagicMock()
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    writer.wait_closed = AsyncMock()
    
    hp = Honeypot()
    hp.storage = MagicMock()
    
    await hp.handle_connection(reader, writer)
    
    assert not hp.storage.record.called
    assert writer.close.called

@pytest.mark.asyncio
async def test_honeypot_listen():
    hp = Honeypot()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_server = AsyncMock()
        mock_server.sockets = [MagicMock()]
        mock_server.sockets[0].getsockname.return_value = ("0.0.0.0", 8080)
        mock_start.return_value = mock_server
        
        # We need to stop serve_forever somehow, or just mock it to return immediately
        mock_server.serve_forever.return_value = None
        
        # Use a timeout to ensure it doesn't hang if serve_forever wasn't mocked right
        try:
            await asyncio.wait_for(hp.listen("0.0.0.0", 8080), timeout=0.1)
        except asyncio.TimeoutError:
            pass
            
        assert mock_start.called
        assert mock_start.call_args[0][1] == "0.0.0.0"
        assert mock_start.call_args[0][2] == 8080

@pytest.mark.asyncio
async def test_main_function(monkeypatch):
    monkeypatch.setenv("LISTEN_PORTS", "80,443")
    with patch("trap.main.Honeypot") as mock_hp_class:
        mock_hp = mock_hp_class.return_value
        mock_hp.listen = AsyncMock()
        
        from trap.main import main as main_func
        await main_func()
        
        assert mock_hp.listen.call_count == 2
        ports = [call[0][1] for call in mock_hp.listen.call_args_list]
        assert 80 in ports
        assert 443 in ports

@pytest.mark.asyncio
async def test_integration_server(tmp_path):
    log_file = tmp_path / "integration.log"
    os.environ["LOG_FILE"] = str(log_file)
    os.environ["STORAGE_TYPE"] = "file"
    
    hp = Honeypot()
    
    # Start server in background
    server = await asyncio.start_server(hp.handle_connection, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    
    async def run_server():
        async with server:
            await server.serve_forever()
            
    server_task = asyncio.create_task(run_server())
    
    # Connect to server
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.write(b"Hello Honeypot")
    await writer.drain()
    
    response = await reader.read(100)
    assert b"OK" in response
    
    writer.close()
    await writer.wait_closed()
    
    # Stop server
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
    
    # Check log file
    assert os.path.exists(log_file)
    with open(log_file, "r") as f:
        content = f.read()
        assert "Hello Honeypot" in content
        assert "unknown" in content
