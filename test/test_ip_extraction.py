import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock
from trap.main import Honeypot

@pytest.fixture
def mock_honeypot(monkeypatch, tmp_path):
    monkeypatch.setenv("STORAGE_TYPE", "file")
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "test.log"))
    monkeypatch.setenv("TRUSTED_PROXIES", "10.0.0.0/8,192.168.1.100")
    hp = Honeypot()
    hp.storage = MagicMock()
    return hp

@pytest.mark.asyncio
async def test_trusted_proxy_x_forwarded_for(mock_honeypot):
    reader = AsyncMock()
    reader.read.side_effect = [b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.1, 10.0.0.1\r\n\r\n", b""]
    
    writer = MagicMock()
    writer.get_extra_info.return_value = ("10.0.0.5", 12345)
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    
    await mock_honeypot.handle_connection(reader, writer)
    
    args = mock_honeypot.storage.record.call_args[0]
    assert args[1] == "203.0.113.1"

@pytest.mark.asyncio
async def test_untrusted_proxy_x_forwarded_for(mock_honeypot):
    reader = AsyncMock()
    reader.read.side_effect = [b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Forwarded-For: 203.0.113.1\r\n\r\n", b""]
    
    writer = MagicMock()
    writer.get_extra_info.return_value = ("172.16.0.5", 12345) # Not in trusted proxy list
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    
    await mock_honeypot.handle_connection(reader, writer)
    
    args = mock_honeypot.storage.record.call_args[0]
    assert args[1] == "172.16.0.5" # Should record the untrusted proxy's IP

@pytest.mark.asyncio
async def test_trusted_proxy_proxy_protocol(mock_honeypot):
    reader = AsyncMock()
    reader.read.side_effect = [b"PROXY TCP4 198.51.100.22 203.0.113.7 35646 80\r\nGET / HTTP/1.1\r\n\r\n", b""]
    
    writer = MagicMock()
    writer.get_extra_info.return_value = ("192.168.1.100", 12345)
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    
    await mock_honeypot.handle_connection(reader, writer)
    
    args = mock_honeypot.storage.record.call_args[0]
    assert args[1] == "198.51.100.22"
    assert args[2] == b"GET / HTTP/1.1\r\n\r\n" # Payload should be stripped off PROXY line

@pytest.mark.asyncio
async def test_trust_all_proxies(monkeypatch, tmp_path):
    monkeypatch.setenv("STORAGE_TYPE", "file")
    monkeypatch.setenv("LOG_FILE", str(tmp_path / "test2.log"))
    monkeypatch.setenv("TRUSTED_PROXIES", "*")
    hp = Honeypot()
    hp.storage = MagicMock()
    
    reader = AsyncMock()
    reader.read.side_effect = [b"GET / HTTP/1.1\r\nHost: example.com\r\nX-Real-IP: 8.8.8.8\r\n\r\n", b""]
    
    writer = MagicMock()
    writer.get_extra_info.return_value = ("1.2.3.4", 12345)
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    
    await hp.handle_connection(reader, writer)
    
    args = hp.storage.record.call_args[0]
    assert args[1] == "8.8.8.8"

@pytest.mark.asyncio
async def test_newline_only_headers(mock_honeypot):
    reader = AsyncMock()
    # Using only \n instead of \r\n
    reader.read.side_effect = [b"GET / HTTP/1.1\nHost: example.com\nX-Forwarded-For: 1.1.1.1\n\n", b""]
    
    writer = MagicMock()
    writer.get_extra_info.return_value = ("10.0.0.5", 12345)
    writer.drain = AsyncMock()
    writer.wait_closed = AsyncMock()
    
    await mock_honeypot.handle_connection(reader, writer)
    
    args = mock_honeypot.storage.record.call_args[0]
    assert args[1] == "1.1.1.1"
