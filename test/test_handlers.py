import pytest
from trap.handlers.default import DefaultHandler, HTTPHandler

def test_default_handler_identify():
    handler = DefaultHandler()
    assert handler.identify(b"any data") is True
    assert handler.identify(b"") is True

def test_default_handler_handle():
    handler = DefaultHandler()
    proto, decoded, response = handler.handle(b"hello")
    assert proto == "unknown"
    assert decoded == "hello"
    assert response == b"OK\n"

def test_default_handler_handle_invalid_utf8():
    handler = DefaultHandler()
    # 0xff is not valid utf-8
    proto, decoded, response = handler.handle(b"\xff")
    assert proto == "unknown"
    assert decoded == "\ufffd"  # replacement character
    assert response == b"OK\n"

def test_http_handler_identify():
    handler = HTTPHandler()
    assert handler.identify(b"GET / HTTP/1.1") is True
    assert handler.identify(b"POST /data HTTP/1.1") is True
    assert handler.identify(b"\r\nGET / HTTP/1.1") is True
    assert handler.identify(b"SSH-2.0-OpenSSH_8.2p1") is False
    # Ensure SOCKS5 or other protocols containing HTTP verbs are not misidentified
    assert handler.identify(b"\x05\x04\x00\x01\x02\x80\x05\x01\x00\x03\ngithub.com\x00PGET / HTTP/1.0\r\n\r\n") is False

def test_http_handler_handle():
    handler = HTTPHandler()
    proto, decoded, response = handler.handle(b"GET / HTTP/1.1")
    assert proto == "http"
    assert "GET / HTTP/1.1" in decoded
    assert b"HTTP/1.1 200 OK" in response
    assert b"Server: nginx" in response
    assert b"Welcome to nginx!" in response
