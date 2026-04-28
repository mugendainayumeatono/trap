import os
import binascii
from .base import ProtocolHandler

class TLSSession:
    def __init__(self):
        self.ccs_received = False

class TLSHandler(ProtocolHandler):
    def __init__(self):
        self.sessions = {}
        self.cert_der = self._load_cert()

    def _load_cert(self):
        cert_path = os.getenv("TLS_CERT_PATH", "/app/certs/cert.der")
        try:
            if os.path.exists(cert_path):
                with open(cert_path, "rb") as f: return f.read()
        except Exception as e:
            print(f"Error loading TLS certificate from {cert_path}: {e}")
        return b""

    def identify(self, data: bytes) -> bool:
        return len(data) >= 6 and data[0] == 0x16 and data[1] == 0x03

    def _build_handshake(self, handshake_type: int, payload: bytes) -> bytes:
        return bytes([handshake_type]) + len(payload).to_bytes(3, "big") + payload

    def _build_record(self, content_type: int, version: bytes, payload: bytes) -> bytes:
        return bytes([content_type]) + version + len(payload).to_bytes(2, "big") + payload

    def handle(self, data: bytes, session_id: str = "") -> tuple[str, str, bytes]:
        if session_id not in self.sessions:
            self.sessions[session_id] = TLSSession()
        
        session = self.sessions[session_id]
        
        try:
            # Handle TLS Records
            offset = 0
            all_responses = b""
            all_decoded = []

            while offset < len(data):
                if len(data) < offset + 5: 
                    break
                    
                content_type = data[offset]
                version = data[offset+1:offset+3]
                length = int.from_bytes(data[offset+3:offset+5], "big")
                
                # BOUNDARY CHECK: Ensure the full TLS record payload is available
                if offset + 5 + length > len(data):
                    break
                    
                payload = data[offset+5:offset+5+length]
                offset += 5 + length
                
                if content_type == 0x16: # Handshake
                    if session.ccs_received:
                        # This is the encrypted Finished message from the client
                        all_decoded.append("Client Finished (Encrypted)")
                        
                        # Simulate the server's encryption confirmation
                        ccs_record = self._build_record(0x14, version, b"\x01")
                        
                        dummy_encrypted_finished = os.urandom(40)
                        finished_record = self._build_record(0x16, version, dummy_encrypted_finished)
                        
                        all_responses += ccs_record + finished_record
                        all_decoded.append("Server Finished (Simulated)")
                        
                        # Handshake complete (from honeypot's perspective), clean up session
                        if session_id in self.sessions: del self.sessions[session_id]
                        return "tls", " | ".join(all_decoded), all_responses
                    else:
                        res_proto, res_dec, res_bytes = self._handle_handshake(payload, version, session)
                        all_responses += res_bytes
                        all_decoded.append(res_dec)
                        
                elif content_type == 0x14: # Change Cipher Spec
                    all_decoded.append("Change Cipher Spec")
                    session.ccs_received = True
                    
                elif content_type == 0x15: # Alert
                    all_decoded.append(f"Alert: {payload.hex()}")
                    if session_id in self.sessions: del self.sessions[session_id]
                    return "tls", " | ".join(all_decoded), b""
                    
                elif content_type == 0x17: # Application Data
                    all_decoded.append("Application Data (Encrypted)")
            
            return "tls", " | ".join(all_decoded) if all_decoded else "Incomplete TLS Record", all_responses

        except Exception as e:
            if session_id in self.sessions: del self.sessions[session_id]
            return "tls", f"Error: {e}", b""

    def _handle_handshake(self, payload: bytes, version: bytes, session: TLSSession) -> tuple[str, str, bytes]:
        # BOUNDARY CHECK: Ensure we can read the Handshake header
        if len(payload) < 4:
            return "tls", "Malformed Handshake (too short)", b""
            
        h_type = payload[0]
        h_len = int.from_bytes(payload[1:4], "big")
        
        # BOUNDARY CHECK: Ensure the Handshake payload matches its declared length
        if len(payload) < 4 + h_len:
            return "tls", "Malformed Handshake (length mismatch)", b""
            
        h_payload = payload[4:4+h_len]
        
        if h_type == 1: # Client Hello
            # BOUNDARY CHECK: Minimal length of Client Hello (Version + Random + SID Length)
            if len(h_payload) < 35:
                return "tls", "Malformed Client Hello (too short)", b""
                
            client_version = h_payload[0:2]
            
            # Session ID length is at offset 34 (2 bytes version + 32 bytes random)
            sid_len = h_payload[34]
            offset = 35 + sid_len
            
            # BOUNDARY CHECK: Ensure we can read cipher suites length
            if len(h_payload) < offset + 2:
                return "tls", "Malformed Client Hello (no cipher suites)", b""
                
            # Cipher Suites
            cs_len = int.from_bytes(h_payload[offset:offset+2], "big")
            offset += 2
            
            # BOUNDARY CHECK: Ensure cipher suites data is fully available
            if len(h_payload) < offset + cs_len:
                return "tls", "Malformed Client Hello (cipher suites length mismatch)", b""
                
            client_suites = [h_payload[i:i+2] for i in range(offset, offset+cs_len, 2)]
            offset += cs_len
            
            # BOUNDARY CHECK: Ensure we can read compression methods length
            if len(h_payload) < offset + 1:
                return "tls", "Malformed Client Hello (no compression methods)", b""
                
            # Compression
            comp_len = h_payload[offset]
            offset += 1 + comp_len
            
            # BOUNDARY CHECK: Ensure compression methods data is fully available
            if len(h_payload) < offset:
                return "tls", "Malformed Client Hello (compression methods length mismatch)", b""
            
            # Extensions
            supported_groups = []
            sig_algs = []
            if len(h_payload) >= offset + 2:
                ext_len = int.from_bytes(h_payload[offset:offset+2], "big")
                offset += 2
                
                # BOUNDARY CHECK: Protect against out-of-bounds extension parsing
                ext_end = min(offset + ext_len, len(h_payload))
                
                while offset + 4 <= ext_end:
                    ext_type = int.from_bytes(h_payload[offset:offset+2], "big")
                    ext_data_len = int.from_bytes(h_payload[offset+2:offset+4], "big")
                    offset += 4
                    
                    # BOUNDARY CHECK: Prevent reading past the extension boundary
                    if offset + ext_data_len > ext_end:
                        break
                        
                    ext_data = h_payload[offset:offset+ext_data_len]
                    
                    if ext_type == 10: # supported_groups
                        if len(ext_data) >= 2:
                            g_len = int.from_bytes(ext_data[0:2], "big")
                            if g_len <= len(ext_data) - 2:
                                supported_groups = [ext_data[i:i+2] for i in range(2, 2+g_len, 2)]
                    elif ext_type == 13: # signature_algorithms
                        if len(ext_data) >= 2:
                            s_len = int.from_bytes(ext_data[0:2], "big")
                            if s_len <= len(ext_data) - 2:
                                sig_algs = [ext_data[i:i+2] for i in range(2, 2+s_len, 2)]
                    offset += ext_data_len
            
            # To "support all", we pick the client's very first preferred suite
            cipher_suite = client_suites[0] if client_suites else b"\x00\x9c"
            selected_group = supported_groups[0] if supported_groups else b"\x00\x17"
            selected_sig = sig_algs[0] if sig_algs else b"\x04\x01"
            
            # Server Hello
            server_random = os.urandom(32)
            
            # Ensure safe indexing for sid extraction
            sid_data = h_payload[35:35+sid_len] if sid_len > 0 else b""
            
            sh_payload = client_version + server_random + bytes([sid_len]) + sid_data + cipher_suite + b"\x00"
            sh_handshake = self._build_handshake(2, sh_payload)
            
            # Certificate
            if not self.cert_der:
                return "tls", "TLS Client Hello (No Cert Loaded)", b""
            cert_list = len(self.cert_der).to_bytes(3, "big") + self.cert_der
            cert_payload = len(cert_list).to_bytes(3, "big") + cert_list
            cert_handshake = self._build_handshake(11, cert_payload)
            
            # Server Key Exchange (if ECDHE suite)
            extra_handshakes = b""
            if cipher_suite[0] == 0xc0:
                dummy_pubkey = b"\x04" + os.urandom(64)
                ske_payload = b"\x03" + selected_group + bytes([len(dummy_pubkey)]) + dummy_pubkey
                if client_version >= b"\x03\x03":
                    ske_payload += selected_sig
                ske_payload += b"\x00\x40" + (b"\x00" * 64)
                extra_handshakes = self._build_handshake(12, ske_payload)
                
            # Server Hello Done
            shd_handshake = self._build_handshake(14, b"")
            
            response = self._build_record(0x16, version, sh_handshake + cert_handshake + extra_handshakes + shd_handshake)
            
            return "tls", f"Client Hello {client_version.hex()} | Suite: {cipher_suite.hex()}", response

        elif h_type == 16: # Client Key Exchange
            return "tls", "Client Key Exchange", b""

        return "tls", f"Handshake Type {h_type}", b""

    def cleanup(self, session_id: str = "") -> None:
        if session_id in self.sessions:
            del self.sessions[session_id]
