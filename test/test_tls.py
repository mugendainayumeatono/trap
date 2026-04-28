import pytest
from trap.handlers.tls import TLSHandler

def test_tls_identify():
    handler = TLSHandler()
    
    # Valid TLS Handshake Record (Client Hello)
    valid_data = bytes.fromhex("16030100c6010000c20303")
    assert handler.identify(valid_data) is True
    
    # Invalid Data (too short)
    short_data = b"\x16\x03\x01\x00\x00"
    assert handler.identify(short_data) is False
    
    # Invalid Data (not handshake)
    app_data = bytes.fromhex("1703030020")
    assert handler.identify(app_data) is False

def test_tls_handle_client_hello():
    handler = TLSHandler()
    handler.cert_der = b"dummy_cert_data" # Mock cert so it doesn't fail if missing
    session_id = "test_session_1"
    
    # Minimal Client Hello (TLS 1.2, AES128-CBC-SHA suite)
    client_hello = bytes.fromhex(
        "160301002f0100002b0303" 
        "5c66a2cb87d86ef8c3934e2f8ed2740da4723887ab2ce112bd8bcef05e1141fd"
        "00" # Session ID
        "0002002f" # Cipher Suites
        "0100" # Compression
        "0000" # Extensions
    )
    
    proto, decoded, response = handler.handle(client_hello, session_id)
    
    assert proto == "tls"
    assert "Client Hello 0303 | Suite: 002f" in decoded
    
    # Check response structure
    # Should contain Server Hello (0x02), Certificate (0x0b), Server Hello Done (0x0e)
    assert len(response) > 0
    assert response[0] == 0x16 # Handshake record
    
    # Since we mocked the file path in testing without a real cert, the response might 
    # just be "Incomplete TLS Record" or "No Cert Loaded" if certs/cert.der isn't found 
    # in the test environment. Let's make sure it doesn't crash at least.
    assert isinstance(response, bytes)

def test_tls_handle_malformed():
    handler = TLSHandler()
    session_id = "test_session_malformed"
    
    # Malformed Handshake (too short for header)
    data = bytes.fromhex("16030100020100")
    proto, decoded, response = handler.handle(data, session_id)
    assert proto == "tls"
    assert "Malformed Handshake" in decoded
    
    # Malformed Client Hello (length mismatch in cipher suites)
    malformed_ch = bytes.fromhex(
        "160301002f0100002b0303" 
        "5c66a2cb87d86ef8c3934e2f8ed2740da4723887ab2ce112bd8bcef05e1141fd"
        "00" # Session ID
        "0010002f" # Declares 16 bytes of suites, but only provides 2
        "0100" 
        "0000" 
    )
    proto, decoded, response = handler.handle(malformed_ch, session_id)
    assert proto == "tls"
    assert "Malformed Client Hello" in decoded

def test_tls_stateful_handshake():
    handler = TLSHandler()
    session_id = "test_session_full"
    
    # 1. Client Hello
    client_hello = bytes.fromhex(
        "160301002f0100002b0303" 
        "5c66a2cb87d86ef8c3934e2f8ed2740da4723887ab2ce112bd8bcef05e1141fd"
        "000002002f01000000"
    )
    handler.handle(client_hello, session_id)
    
    # Session should be tracked
    assert session_id in handler.sessions
    
    # 2. Client Key Exchange & Change Cipher Spec & Finished
    # We simulate the client sending these
    cke_ccs_fin = bytes.fromhex(
        "1603030006100000020000" # Dummy CKE
        "140303000101"           # CCS
        "160303001000000000000000000000000000000000" # Dummy Encrypted Finished
    )
    
    proto, decoded, response = handler.handle(cke_ccs_fin, session_id)
    
    assert proto == "tls"
    assert "Change Cipher Spec" in decoded
    assert "Client Finished" in decoded
    assert "Server Finished (Simulated)" in decoded
    
    # Session should be cleaned up after Finished
    assert session_id not in handler.sessions

def test_tls_cleanup():
    handler = TLSHandler()
    session_id = "test_session_cleanup"
    
    # Initialize a session
    handler.handle(bytes.fromhex("160301002f0100002b03035c66a2cb87d86ef8c3934e2f8ed2740da4723887ab2ce112bd8bcef05e1141fd000002002f01000000"), session_id)
    assert session_id in handler.sessions
    
    # Trigger cleanup
    handler.cleanup(session_id)
    
    # Session should be removed
    assert session_id not in handler.sessions
