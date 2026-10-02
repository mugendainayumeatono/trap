import os
import binascii
import hashlib
import hmac
import struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .base import ProtocolHandler

def p_hash(secret: bytes, seed: bytes, output_len: int, hash_func=hashlib.sha256) -> bytes:
    result = bytearray()
    a = seed
    while len(result) < output_len:
        a = hmac.new(secret, a, hash_func).digest()
        result.extend(hmac.new(secret, a + seed, hash_func).digest())
    return bytes(result[:output_len])

def tls_12_prf(secret: bytes, label: bytes, seed: bytes, output_len: int) -> bytes:
    return p_hash(secret, label + seed, output_len, hashlib.sha256)

class TLSSession:
    def __init__(self):
        self.ccs_received = False
        self.client_random = b""
        self.server_random = b""
        self.cipher_suite = b""
        self.client_version = b"\x03\x03"
        self.handshake_messages = bytearray()
        self.ecdh_private_key = None
        self.master_secret = None
        self.server_write_key = None
        self.server_write_iv = None

class TLSHandler(ProtocolHandler):
    def __init__(self):
        self.sessions = {}
        self.cert_der = self._load_cert()
        self.private_key = self._load_key()

    def _load_cert(self):
        cert_path = os.getenv("TLS_CERT_PATH", "/app/certs/cert.der")
        if not os.path.exists(cert_path):
            local_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "certs", "cert.der")
            if os.path.exists(local_path):
                cert_path = local_path
        try:
            if os.path.exists(cert_path):
                with open(cert_path, "rb") as f: return f.read()
        except Exception as e:
            print(f"Error loading TLS certificate from {cert_path}: {e}")
        return b""

    def _load_key(self):
        key_path = os.getenv("TLS_KEY_PATH", "/app/certs/cert.key")
        if not os.path.exists(key_path):
            local_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "certs", "cert.key")
            if os.path.exists(local_path):
                key_path = local_path
        try:
            if os.path.exists(key_path):
                with open(key_path, "rb") as f:
                    return serialization.load_pem_private_key(f.read(), password=None)
        except Exception as e:
            print(f"Error loading TLS private key from {key_path}: {e}")
        return None

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
                        
                        # Simulate the server's encryption confirmation (CCS)
                        ccs_record = self._build_record(0x14, version, b"\x01")
                        
                        # Calculate PRF verify_data based on accumulated handshake messages
                        handshake_hash = hashlib.sha256(session.handshake_messages).digest()
                        if session.master_secret:
                            verify_data = tls_12_prf(session.master_secret, b"server finished", handshake_hash, 12)
                        else:
                            verify_data = os.urandom(12)
                            
                        finished_handshake = bytes([20, 0, 0, 12]) + verify_data
                        
                        # If session keys are available, encrypt Finished with AES-GCM; otherwise fallback gracefully
                        if session.server_write_key and session.server_write_iv:
                            try:
                                explicit_nonce = os.urandom(8)
                                nonce = session.server_write_iv + explicit_nonce
                                seq_num = 0
                                aad = struct.pack(">Q", seq_num) + bytes([0x16]) + version + struct.pack(">H", len(finished_handshake))
                                ciphertext = AESGCM(session.server_write_key).encrypt(nonce, finished_handshake, aad)
                                finished_record = self._build_record(0x16, version, explicit_nonce + ciphertext)
                            except Exception:
                                dummy_encrypted_finished = os.urandom(40)
                                finished_record = self._build_record(0x16, version, dummy_encrypted_finished)
                        else:
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
            client_random = h_payload[2:34]
            session.client_random = client_random
            session.client_version = client_version
            
            # Record Client Hello handshake in session message history
            session.handshake_messages.extend(payload[:4+h_len])
            
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
            
            # Pick client's preferred suite
            cipher_suite = client_suites[0] if client_suites else b"\x00\x9c"
            session.cipher_suite = cipher_suite
            selected_group = supported_groups[0] if supported_groups else b"\x00\x17"
            selected_sig = sig_algs[0] if sig_algs else b"\x04\x01"
            
            # Server Hello
            server_random = os.urandom(32)
            session.server_random = server_random
            
            # Ensure safe indexing for sid extraction
            sid_data = h_payload[35:35+sid_len] if sid_len > 0 else b""
            
            sh_payload = client_version + server_random + bytes([sid_len]) + sid_data + cipher_suite + b"\x00"
            sh_handshake = self._build_handshake(2, sh_payload)
            session.handshake_messages.extend(sh_handshake)
            
            # Certificate
            if not self.cert_der:
                return "tls", "TLS Client Hello (No Cert Loaded)", b""
            cert_list = len(self.cert_der).to_bytes(3, "big") + self.cert_der
            cert_payload = len(cert_list).to_bytes(3, "big") + cert_list
            cert_handshake = self._build_handshake(11, cert_payload)
            session.handshake_messages.extend(cert_handshake)
            
            # Server Key Exchange (if ECDHE suite: 0xc0xx or 0xccxx)
            extra_handshakes = b""
            is_ecdhe = (cipher_suite[0] == 0xc0 and len(cipher_suite) == 2 and cipher_suite[1] not in (0x12, 0x0a)) or \
                       (cipher_suite[0] == 0xcc and len(cipher_suite) == 2 and cipher_suite[1] in (0xa8, 0xa9))
            
            if is_ecdhe:
                # Generate ephemeral key according to selected curve
                if selected_group == b"\x00\x1d": # x25519
                    session.ecdh_private_key = x25519.X25519PrivateKey.generate()
                    pub_bytes = session.ecdh_private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )
                else: # Default secp256r1 (0x0017)
                    session.ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
                    pub_bytes = session.ecdh_private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint
                    )
                
                # ServerECDHParams: curve_type (3 = named_curve) + named_curve (2 bytes) + point_len + point
                ske_params = b"\x03" + selected_group + bytes([len(pub_bytes)]) + pub_bytes
                
                # Sign params with server's RSA private key if available
                if self.private_key:
                    try:
                        to_sign = session.client_random + session.server_random + ske_params
                        sig = self.private_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
                        ske_payload = ske_params + selected_sig + len(sig).to_bytes(2, "big") + sig
                    except Exception:
                        ske_payload = ske_params + selected_sig + b"\x00\x40" + (b"\x00" * 64)
                else:
                    ske_payload = ske_params
                    if client_version >= b"\x03\x03":
                        ske_payload += selected_sig
                    ske_payload += b"\x00\x40" + (b"\x00" * 64)
                    
                extra_handshakes = self._build_handshake(12, ske_payload)
                session.handshake_messages.extend(extra_handshakes)
                
            # Server Hello Done
            shd_handshake = self._build_handshake(14, b"")
            session.handshake_messages.extend(shd_handshake)
            
            response = self._build_record(0x16, version, sh_handshake + cert_handshake + extra_handshakes + shd_handshake)
            
            return "tls", f"Client Hello {client_version.hex()} | Suite: {cipher_suite.hex()}", response

        elif h_type == 16: # Client Key Exchange
            session.handshake_messages.extend(payload[:4+h_len])
            
            pms = None
            if session.ecdh_private_key:
                try:
                    # Client public key is preceded by 1-byte length in ECDH CKE
                    client_pub = h_payload[1:] if len(h_payload) > 1 and h_payload[0] == len(h_payload) - 1 else h_payload
                    if isinstance(session.ecdh_private_key, x25519.X25519PrivateKey):
                        peer_key = x25519.X25519PublicKey.from_public_bytes(client_pub)
                        pms = session.ecdh_private_key.exchange(peer_key)
                    elif isinstance(session.ecdh_private_key, ec.EllipticCurvePrivateKey):
                        peer_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub)
                        pms = session.ecdh_private_key.exchange(ec.ECDH(), peer_key)
                except Exception:
                    pass
            elif self.private_key:
                try:
                    # RSA EncryptedPreMasterSecret has 2-byte length prefix
                    enc_pms = h_payload[2:] if len(h_payload) > 2 and int.from_bytes(h_payload[:2], "big") == len(h_payload) - 2 else h_payload
                    pms = self.private_key.decrypt(enc_pms, padding.PKCS1v15())
                except Exception:
                    pass

            if not pms:
                # Fallback to deterministic pseudo-secret for simulated/dummy probes
                pms = hashlib.sha256(session.client_random + session.server_random).digest()[:48]

            session.master_secret = tls_12_prf(
                pms,
                b"master secret",
                session.client_random + session.server_random,
                48
            )
            key_block = tls_12_prf(
                session.master_secret,
                b"key expansion",
                session.server_random + session.client_random,
                40
            )
            session.server_write_key = key_block[16:32]
            session.server_write_iv = key_block[36:40]
            
            return "tls", "Client Key Exchange", b""

        return "tls", f"Handshake Type {h_type}", b""

    def cleanup(self, session_id: str = "") -> None:
        if session_id in self.sessions:
            del self.sessions[session_id]
