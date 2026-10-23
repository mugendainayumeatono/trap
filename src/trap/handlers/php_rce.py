import base64
import email.utils
import hashlib
import json
import os
import re
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class PHPAttackState:
    attack_id: str
    client_ip: str
    phpsessid: str = ""
    current_stage: str = "STAGE_1_RECON"
    worker_corrupted: bool = False
    step_index: int = 0
    cves_triggered: List[str] = field(default_factory=list)
    virtual_files: Dict[str, str] = field(default_factory=dict)
    timeline: List[Dict[str, object]] = field(default_factory=list)
    last_updated: float = field(default_factory=time.time)

    def add_cve(self, cve_id: str) -> None:
        if cve_id not in self.cves_triggered:
            self.cves_triggered.append(cve_id)


class PHPAttackTracker:
    """
    Tracks multi-stage PHP2Shell (CVE-2026-109618 & CVE-2026-109619) attack chains
    across multiple HTTP requests and TCP connections by correlating client IP
    and PHPSESSID.
    """

    def __init__(self, ttl_seconds: float = 600.0):
        self.ttl_seconds = ttl_seconds
        self.by_ip: Dict[str, PHPAttackState] = {}
        self.by_sessid: Dict[str, PHPAttackState] = {}

    def _evict_expired(self) -> None:
        now = time.time()
        expired_ips = [
            ip for ip, st in self.by_ip.items() if now - st.last_updated > self.ttl_seconds
        ]
        for ip in expired_ips:
            st = self.by_ip.pop(ip, None)
            if st and st.phpsessid:
                self.by_sessid.pop(st.phpsessid, None)

        expired_sids = [
            sid for sid, st in self.by_sessid.items() if now - st.last_updated > self.ttl_seconds
        ]
        for sid in expired_sids:
            self.by_sessid.pop(sid, None)

    @staticmethod
    def extract_ip_from_session_id(session_id: str) -> str:
        if not session_id:
            return "unknown"
        if ":" in session_id:
            # Handle IPv4 "1.2.3.4:12345" or IPv6 "::1:12345"
            head, tail = session_id.rsplit(":", 1)
            if tail.isdigit():
                return head
        return session_id

    def get_or_create(self, session_id: str, phpsessid: str = "") -> PHPAttackState:
        self._evict_expired()
        client_ip = self.extract_ip_from_session_id(session_id)

        state = None
        if phpsessid and phpsessid in self.by_sessid:
            state = self.by_sessid[phpsessid]
        elif client_ip in self.by_ip:
            state = self.by_ip[client_ip]

        if state is None:
            short_id = uuid.uuid4().hex[:10]
            sid = phpsessid or hashlib.md5(f"{client_ip}-{short_id}".encode()).hexdigest()[:26]
            state = PHPAttackState(
                attack_id=f"php2shell-{short_id}",
                client_ip=client_ip,
                phpsessid=sid,
            )
            self.by_ip[client_ip] = state
            self.by_sessid[sid] = state
        else:
            state.last_updated = time.time()
            if phpsessid and phpsessid != state.phpsessid:
                state.phpsessid = phpsessid
                self.by_sessid[phpsessid] = state
            self.by_ip[client_ip] = state

        return state


class PHPSandboxSimulator:
    """
    Safely parses, decodes, and simulates execution of PHP code and OS shell commands
    delivered during PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exploitation.
    Never executes untrusted code on the host.
    """

    PHP_VERSION = "8.3.34"
    SERVER_BANNER = "nginx/1.18.0 (Ubuntu)"
    UNAME_OUTPUT = (
        "Linux ubuntu-web01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC "
        "x86_64 x86_64 x86_64 GNU/Linux"
    )
    ID_OUTPUT = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    PASSWD_OUTPUT = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    )

    # Regex patterns for payload extraction
    B64_CALL_RE = re.compile(
        r"base64_decode\s*\(\s*['\"]([A-Za-z0-9+/=\s]{4,})['\"]\s*\)", re.IGNORECASE
    )
    PHP_EXEC_RE = re.compile(
        r"(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
        re.IGNORECASE,
    )
    FILE_PUT_RE = re.compile(
        r"file_put_contents\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*(.+?)\)",
        re.IGNORECASE | re.DOTALL,
    )
    SHELL_REDIRECT_PHP_RE = re.compile(
        r"echo\s+['\"](<\?php.*?\?>)['\"]\s*>\s*([^\s;&|]+)",
        re.IGNORECASE | re.DOTALL,
    )
    URL_IOC_RE = re.compile(r"https?://[^\s'\"<>\\)+]+", re.IGNORECASE)
    SHELL_CMD_PATTERN = re.compile(
        r"(?:^|[;&|\n`$(])\s*((?:id|whoami|uname(?:\s+-[a-zA-Z]+)?|pwd|ls(?:\s+-[a-zA-Z]+)?|"
        r"cat\s+/etc/[a-zA-Z0-9_./-]+|echo\s+[^\r\n;&|]+|printf\s+[^\r\n;&|]+|"
        r"curl\s+[^\r\n;&|]+|wget\s+[^\r\n;&|]+|php\s+-[a-zA-Z]+))\b",
        re.IGNORECASE,
    )

    @classmethod
    def decode_nested_base64(cls, text: str) -> List[str]:
        decoded_items = []
        current = text
        for _ in range(3):
            matches = cls.B64_CALL_RE.findall(current)
            if not matches:
                break
            next_layer = []
            for raw_b64 in matches:
                cleaned = re.sub(r"\s+", "", raw_b64)
                try:
                    dec = base64.b64decode(cleaned).decode("utf-8", errors="replace")
                    if dec and dec not in decoded_items:
                        decoded_items.append(dec)
                        next_layer.append(dec)
                except Exception:
                    pass
            if not next_layer:
                break
            current = "\n".join(next_layer)
        return decoded_items

    @classmethod
    def extract_artifacts(
        cls, request_path: str, query_string: str, headers_text: str, body_text: str
    ) -> Dict[str, List[str]]:
        unquoted_query = urllib.parse.unquote_plus(query_string)
        unquoted_body = urllib.parse.unquote_plus(body_text)
        combined = f"{unquoted_query}\n{body_text}\n{unquoted_body}"

        decoded_payloads = cls.decode_nested_base64(combined)

        # Also check if form parameters like cmd= or c= or 0= carry raw base64 or commands
        param_Regex = re.compile(r"(?:^|[&?\r\n])(?:cmd|c|exec|command|e|0)=([^&\r\n]+)", re.I)
        for val in param_Regex.findall(f"{query_string}\n{body_text}"):
            unq = urllib.parse.unquote_plus(val).strip()
            if unq and unq not in decoded_payloads:
                decoded_payloads.append(unq)
            # Try base64 decoding if it looks like base64
            if len(unq) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=]+", unq):
                try:
                    b64_dec = base64.b64decode(unq).decode("utf-8", errors="replace")
                    if b64_dec and b64_dec.isprintable() and b64_dec not in decoded_payloads:
                        decoded_payloads.append(b64_dec)
                except Exception:
                    pass

        all_inspection_text = combined + "\n" + "\n".join(decoded_payloads)

        # Extract PHP snippets
        php_tags = re.findall(r"<\?php.*?\?>", all_inspection_text, re.IGNORECASE | re.DOTALL)
        for tag in php_tags:
            if tag not in decoded_payloads:
                decoded_payloads.append(tag)

        # Extract commands inside PHP execution functions
        commands: List[str] = []
        for cmd in cls.PHP_EXEC_RE.findall(all_inspection_text):
            for sub_cmd in [c.strip() for c in re.split(r"[;\n]", cmd) if c.strip()]:
                if sub_cmd not in commands:
                    commands.append(sub_cmd)

        # Extract standalone OS shell commands
        for match in cls.SHELL_CMD_PATTERN.findall(all_inspection_text):
            cmd_clean = match.strip()
            if cmd_clean and cmd_clean not in commands:
                commands.append(cmd_clean)

        # Extract dropped files via file_put_contents or shell redirection or multipart .php upload
        dropped_files: List[Tuple[str, str]] = []
        for fname, content_expr in cls.FILE_PUT_RE.findall(all_inspection_text):
            norm_path = re.sub(r"^(?:/var/www/html/|/var/www/|/usr/share/nginx/html/|\./)+", "", fname.strip())
            clean_name = "/" + norm_path.lstrip("/")
            # Check if content_expr uses base64_decode
            b64_inner = cls.decode_nested_base64(content_expr)
            file_body = b64_inner[0] if b64_inner else content_expr.strip("'\" ")
            dropped_files.append((clean_name, file_body))

        for php_code, fname in cls.SHELL_REDIRECT_PHP_RE.findall(all_inspection_text):
            base_name = os.path.basename(fname.strip("'\""))
            clean_name = "/" + base_name.lstrip("/")
            dropped_files.append((clean_name, php_code))

        # Check multipart uploaded .php filenames
        for fname in re.findall(r'filename=["\']([^"\']+\.php\d*)["\']', body_text, re.IGNORECASE):
            clean_name = "/" + os.path.basename(fname).lstrip("/")
            dropped_files.append((clean_name, "<?php /* uploaded multipart payload */ ?>"))

        # Extract URLs / IOCs
        iocs: List[str] = []
        for url in cls.URL_IOC_RE.findall(all_inspection_text):
            if "infrawat.ch" not in url and url not in iocs:
                iocs.append(url)

        return {
            "commands": commands,
            "decoded_payloads": decoded_payloads,
            "dropped_files": [f[0] for f in dropped_files],
            "dropped_file_map": dict(dropped_files),
            "iocs": iocs,
        }

    @classmethod
    def simulate_output(
        cls,
        artifacts: Dict[str, object],
        full_inspection_text: str,
        state: PHPAttackState,
    ) -> str:
        outputs: List[str] = []

        # Register any dropped virtual webshells into the attacker's state
        dropped_map: Dict[str, str] = artifacts.get("dropped_file_map", {})  # type: ignore
        for path, content in dropped_map.items():
            state.virtual_files[path] = content

        # Check for phpinfo()
        if re.search(r"phpinfo\s*\(\s*\)", full_inspection_text, re.IGNORECASE):
            outputs.append(
                f"<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>"
                f"<h1>PHP Version {cls.PHP_VERSION}</h1>"
                f"<table>"
                f"<tr><td>System</td><td>{cls.UNAME_OUTPUT}</td></tr>"
                f"<tr><td>Server API</td><td>Apache 2.0 Handler / FPM/FastCGI</td></tr>"
                f"<tr><td>memory_limit</td><td>128M</td></tr>"
                f"<tr><td>session.upload_progress.enabled</td><td>On</td></tr>"
                f"<tr><td>session.upload_progress.cleanup</td><td>On</td></tr>"
                f"<tr><td>session.upload_progress.prefix</td><td>upload_progress_</td></tr>"
                f"<tr><td>session.upload_progress.name</td><td>PHP_SESSION_UPLOAD_PROGRESS</td></tr>"
                f"</table></body></html>"
            )

        # Check for md5(...) canary verification in PHP
        for md5_arg in re.findall(r"md5\s*\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)", full_inspection_text, re.I):
            outputs.append(hashlib.md5(md5_arg.encode("utf-8")).hexdigest())

        # Check for PHP echo/print string literals (outside shell commands)
        for php_echo in re.findall(
            r"(?:<\?php|;)\s*(?:echo|print)\s+['\"]([^'\"]+)['\"]\s*;",
            full_inspection_text,
            re.IGNORECASE,
        ):
            if php_echo not in outputs:
                outputs.append(php_echo)

        commands: List[str] = artifacts.get("commands", [])  # type: ignore
        for cmd in commands:
            cmd_lower = cmd.lower().strip()
            if cmd_lower == "id":
                outputs.append(cls.ID_OUTPUT)
            elif cmd_lower == "whoami":
                outputs.append("www-data")
            elif cmd_lower.startswith("uname"):
                outputs.append(cls.UNAME_OUTPUT if "-" in cmd_lower else "Linux")
            elif cmd_lower == "pwd":
                outputs.append("/var/www/html")
            elif cmd_lower.startswith("ls"):
                files = ["index.php", "config.php", "upload.php"]
                for vf in state.virtual_files:
                    vname = vf.lstrip("/")
                    if vname and vname not in files:
                        files.append(vname)
                if "-l" in cmd_lower:
                    lines = ["total 24"]
                    for f in files:
                        lines.append(f"-rw-r--r-- 1 www-data www-data 1024 Oct 21 12:00 {f}")
                    outputs.append("\n".join(lines))
                else:
                    outputs.append("  ".join(files))
            elif cmd_lower.startswith("cat /etc/passwd"):
                outputs.append(cls.PASSWD_OUTPUT.rstrip("\n"))
            elif cmd_lower.startswith("php -v"):
                outputs.append(
                    f"PHP {cls.PHP_VERSION} (cli) (built: Oct  1 2026 10:12:00) (NTS)\n"
                    f"Copyright (c) The PHP Group\n"
                    f"Zend Engine v4.3.34, Copyright (c) Zend Technologies"
                )
            elif cmd_lower.startswith("echo ") or cmd_lower.startswith("printf "):
                # Do not echo if it is a file redirect like echo '<?php...?>' > shell.php
                if ">" not in cmd:
                    arg = re.sub(r"^(?:echo|printf)\s+(?:-[neE]+\s+)?", "", cmd, flags=re.I).strip()
                    arg = arg.strip("'\"")
                    if arg and arg not in outputs:
                        outputs.append(arg)
            elif cmd_lower.startswith("curl ") or cmd_lower.startswith("wget "):
                # Simulate silent success of downloader
                pass

        return "\n".join(outputs) + ("\n" if outputs else "")


class HTTPStreamBuffer:
    """
    Buffers multi-packet HTTP POST/PUT requests (especially multipart/form-data used in
    CVE-2026-109618) so that the honeypot does not prematurely emit 200 OK in the middle
    of a multi-chunk exploit upload.
    """

    MAX_BUFFER_SIZE = 65536
    MAX_CHUNKS = 16

    def __init__(self):
        self.data = bytearray()
        self.chunks_count = 0
        self.created_at = time.time()


class PHP2ShellEngine:
    """
    Core detection, state machine, response synthesizer, and audit logger for
    PHP2Shell (CVE-2026-109618 & CVE-2026-109619) and related PHP RCE attacks.
    """

    def __init__(self, tracker: Optional[PHPAttackTracker] = None):
        self.tracker = tracker or PHPAttackTracker()
        self.buffers: Dict[str, HTTPStreamBuffer] = {}

    def cleanup_session(self, session_id: str) -> None:
        buf = self.buffers.pop(session_id, None)
        if buf and buf.data:
            # Ensure state transitions (e.g., OOM worker corruption) are recorded even if
            # the attacker disconnects abruptly after sending a truncated multipart payload.
            try:
                self._analyze_and_respond(bytes(buf.data), session_id)
            except Exception:
                pass

    def is_buffering(self, session_id: str) -> bool:
        return bool(session_id and session_id in self.buffers)

    def process_chunk(
        self, data: bytes, session_id: str = ""
    ) -> Optional[Tuple[str, str, bytes]]:
        """
        Handles incoming HTTP data (potentially across multiple TCP reads).
        Returns (protocol, decoded_content, response_bytes) if handled as a PHP/PHP2Shell
        interaction or buffered fragment, or None if it is a standard non-PHP HTTP request.
        """
        if session_id and session_id in self.buffers:
            buf = self.buffers[session_id]
            buf.data.extend(data)
            buf.chunks_count += 1
            if self._needs_more_chunks(bytes(buf.data), len(data), buf.chunks_count):
                raw_preview = data.decode("utf-8", errors="replace")
                return (
                    "http/php2shell",
                    f"[PHP2SHELL_FRAGMENT chunk={buf.chunks_count} buffered={len(buf.data)}]\n{raw_preview}",
                    b"",
                )
            full_data = bytes(buf.data)
            del self.buffers[session_id]
            return self._analyze_and_respond(full_data, session_id)

        # First chunk on this connection
        if session_id and self._should_start_buffering(data):
            buf = HTTPStreamBuffer()
            buf.data.extend(data)
            buf.chunks_count = 1
            self.buffers[session_id] = buf
            raw_preview = data.decode("utf-8", errors="replace")
            return (
                "http/php2shell",
                f"[PHP2SHELL_FRAGMENT chunk=1 buffered={len(buf.data)}]\n{raw_preview}",
                b"",
            )

        return self._analyze_and_respond(data, session_id)

    def _should_start_buffering(self, data: bytes) -> bool:
        stripped = data.lstrip(b"\r\n")
        if not (stripped.startswith(b"POST ") or stripped.startswith(b"PUT ")):
            return False
        return self._needs_more_chunks(data, len(data), 1)

    def _needs_more_chunks(self, accumulated: bytes, last_read_len: int, chunks_count: int) -> bool:
        if len(accumulated) >= HTTPStreamBuffer.MAX_BUFFER_SIZE:
            return False
        if chunks_count >= HTTPStreamBuffer.MAX_CHUNKS:
            return False

        sep_idx = accumulated.find(b"\r\n\r\n")
        sep_len = 4
        if sep_idx == -1:
            sep_idx = accumulated.find(b"\n\n")
            sep_len = 2

        if sep_idx == -1:
            # Headers not complete yet
            return True

        headers_bytes = accumulated[:sep_idx]
        body_bytes = accumulated[sep_idx + sep_len :]
        headers_str = headers_bytes.decode("latin-1", errors="ignore")

        # Extract Content-Length if present
        cl_match = re.search(r"(?i)(?:^|[\r\n])Content-Length:\s*(\d+)", headers_str)
        content_length = int(cl_match.group(1)) if cl_match else None

        # Extract multipart boundary if present
        b_match = re.search(
            r'(?i)Content-Type:\s*multipart/form-data\s*;[^\r\n]*boundary=["\']?([^"\'\s;\r\n]+)',
            headers_str,
        )
        boundary = b_match.group(1).encode("latin-1", errors="ignore") if b_match else None

        # If a closing multipart boundary is already present, request is complete
        if boundary and (b"--" + boundary + b"--") in body_bytes:
            return False

        # If header explicitly signals intentional single-packet malformed/OOM probe
        if re.search(r"(?i)(?:^|[\r\n])X-PHP2Shell-Malformed:\s*1", headers_str):
            return False

        if content_length is not None:
            if content_length == 0:
                return False
            # Huge Content-Length (> MAX_BUFFER_SIZE, e.g., 128MB OOM trigger in CVE-2026-109618):
            # Only wait if body is completely empty (headers sent in first TCP segment);
            # once any body bytes arrive, process immediately unless the socket read was full (4096).
            if content_length > HTTPStreamBuffer.MAX_BUFFER_SIZE:
                if len(body_bytes) == 0:
                    return True
                return last_read_len >= 4096
            # Normal Content-Length (<= 64KB): wait until declared body bytes arrive
            if len(body_bytes) < content_length:
                return True
            return False

        # No Content-Length, but multipart/form-data without closing boundary yet
        if boundary:
            return True

        # Transfer-Encoding: chunked without final 0 chunk
        if re.search(r"(?i)Transfer-Encoding:\s*chunked", headers_str):
            if not body_bytes.endswith(b"0\r\n\r\n") and not body_bytes.endswith(b"0\n\n"):
                return True

        return False

    def _parse_http_request(self, data: bytes) -> Tuple[str, str, str, str, bytes]:
        sep_idx = data.find(b"\r\n\r\n")
        sep_len = 4
        if sep_idx == -1:
            sep_idx = data.find(b"\n\n")
            sep_len = 2

        if sep_idx != -1:
            header_part = data[:sep_idx].decode("utf-8", errors="replace")
            body_bytes = data[sep_idx + sep_len :]
        else:
            header_part = data.decode("utf-8", errors="replace")
            body_bytes = b""

        lines = header_part.lstrip("\r\n").splitlines()
        request_line = lines[0] if lines else ""
        parts = request_line.split(" ")
        method = parts[0].upper() if parts else "GET"
        raw_target = parts[1] if len(parts) > 1 else "/"
        if "?" in raw_target:
            path, query = raw_target.split("?", 1)
        else:
            path, query = raw_target, ""

        return method, path, query, header_part, body_bytes

    def _extract_phpsessid(self, query: str, headers_text: str, body_text: str) -> str:
        # 1. Cookie header
        m_cookie = re.search(r"(?i)Cookie:[^\r\n]*\bPHPSESSID=([A-Za-z0-9,-]{1,128})", headers_text)
        if m_cookie:
            return m_cookie.group(1)
        # 2. Multipart form field name="PHPSESSID" (CVE-2026-109618 use_only_cookies bypass)
        m_form = re.search(
            r'name=["\']PHPSESSID["\']\s*(?:\r?\n){2,}\s*([^\r\n-]+)',
            body_text,
            re.IGNORECASE,
        )
        if m_form:
            return m_form.group(1).strip()
        # 3. Query string or URL-encoded body
        m_param = re.search(r"(?:^|[&?])PHPSESSID=([A-Za-z0-9,-]{1,128})", f"{query}&{body_text}")
        if m_param:
            return m_param.group(1)
        return ""

    def _is_oom_corruption_trigger(
        self, headers_text: str, body_bytes: bytes, body_text: str, has_upload_progress: bool
    ) -> bool:
        """
        Detects CVE-2026-109618 Out-of-Memory (OOM) / zend_bailout() trigger patterns:
        1. Oversized Content-Length (> 1MB) aiming to trip memory_limit during rfc1867 parsing
        2. Upload progress with malformed/unclosed multipart boundary or truncated part
        3. Deeply nested array variables (e.g., a[b][c][d][e]...) or excessive multipart parts
        4. High-density heap-feng-shui padding or binary fake zval/pointer spray (0x00007f...)
        5. Session serialization injection via PHP_SESSION_UPLOAD_PROGRESS (|O:, |a:, etc.)
        """
        cl_match = re.search(r"(?i)(?:^|[\r\n])Content-Length:\s*(\d+)", headers_text)
        if cl_match and int(cl_match.group(1)) >= 1048576:
            return True

        b_match = re.search(
            r'(?i)Content-Type:\s*multipart/form-data\s*;[^\r\n]*boundary=["\']?([^"\'\s;\r\n]+)',
            headers_text,
        )
        if b_match:
            boundary_bytes = b_match.group(1).encode("latin-1", errors="ignore")
            has_closing = (b"--" + boundary_bytes + b"--") in body_bytes
            # Malformed/unclosed multipart with upload progress or large body
            if has_upload_progress and not has_closing and len(body_bytes) > 0:
                return True
            # Excessive multipart parts (> 10 parts)
            if body_bytes.count(b"--" + boundary_bytes) > 10:
                return True

        # Deeply nested array brackets
        if re.search(r"(\[[^\]]*\]\s*){5,}", body_text):
            return True

        # Large padding (> 2KB) or repeated heap spray patterns with upload_progress or multipart
        if len(body_bytes) >= 2048 and (has_upload_progress or b_match is not None):
            return True

        # Non-ASCII binary ROP / fake pointer patterns (\x7f, \x00\x00\x00) inside multipart
        non_ascii_nulls = body_bytes.count(b"\x00")
        if non_ascii_nulls >= 8 and (has_upload_progress or b_match is not None):
            return True

        # Serialized object/array injection inside PHP_SESSION_UPLOAD_PROGRESS
        if has_upload_progress and re.search(r"(?:\||^)(?:O|C|a|s):\d+:", body_text):
            return True

        return False

    def _analyze_and_respond(
        self, data: bytes, session_id: str
    ) -> Optional[Tuple[str, str, bytes]]:
        method, path, query, headers_text, body_bytes = self._parse_http_request(data)
        body_text = body_bytes.decode("utf-8", errors="replace")
        raw_decoded = data.decode("utf-8", errors="replace")

        client_ip = self.tracker.extract_ip_from_session_id(session_id)
        phpsessid = self._extract_phpsessid(query, headers_text, body_text)

        has_upload_progress = (
            "PHP_SESSION_UPLOAD_PROGRESS" in body_text
            or "PHP_SESSION_UPLOAD_PROGRESS" in query
            or "upload_progress_" in body_text
        )
        is_multipart = bool(re.search(r"(?i)Content-Type:\s*multipart/form-data", headers_text))
        is_php_path = ".php" in path.lower()
        is_cgi_injection = bool(
            re.search(r"(?i)(?:%AD|-d).*(?:allow_url_include|auto_prepend_file)", query)
        )

        # Check if an existing attack state already exists for this IP or PHPSESSID
        existing_state = (
            self.tracker.by_sessid.get(phpsessid)
            if phpsessid
            else self.tracker.by_ip.get(client_ip)
        )

        artifacts = PHPSandboxSimulator.extract_artifacts(path, query, headers_text, body_text)
        has_rce_payload = bool(
            artifacts["commands"]
            or artifacts["decoded_payloads"]
            or artifacts["dropped_files"]
            or re.search(r"phpinfo\s*\(", f"{query}\n{body_text}", re.I)
        )
        is_oom_trigger = self._is_oom_corruption_trigger(
            headers_text, body_bytes, body_text, has_upload_progress
        )

        # Determine if this request is part of a PHP / PHP2Shell interaction
        is_virtual_webshell = bool(
            existing_state and path in existing_state.virtual_files
        )
        is_corrupted_followup = bool(existing_state and existing_state.worker_corrupted)

        if not any(
            [
                has_upload_progress,
                is_oom_trigger,
                has_rce_payload,
                is_virtual_webshell,
                is_corrupted_followup,
                is_cgi_injection,
                is_php_path,
                bool(phpsessid),
            ]
        ):
            # Standard non-PHP HTTP request (e.g. GET / HTTP/1.1)
            return None

        state = self.tracker.get_or_create(session_id, phpsessid)
        state.step_index += 1

        # Stage classification & CVE attribution
        status_code = "200 OK"
        response_body_str = ""

        if is_virtual_webshell or (
            state.current_stage in ("STAGE_3_UAF_RCE", "STAGE_4_POST_EXPLOIT")
            and has_rce_payload
            and not is_oom_trigger
            and not has_upload_progress
        ):
            # Stage 4: Post-Exploitation / Webshell interaction
            stage = "STAGE_4_POST_EXPLOIT"
            state.current_stage = stage
            if not state.cves_triggered:
                state.add_cve("CVE-2026-109618")
                state.add_cve("CVE-2026-109619")
            full_text = f"{query}\n{body_text}\n" + "\n".join(artifacts["decoded_payloads"])
            sim_out = PHPSandboxSimulator.simulate_output(artifacts, full_text, state)
            response_body_str = sim_out if sim_out else "OK\n"

        elif is_oom_trigger and not has_rce_payload:
            # Stage 2: Pure CVE-2026-109618 OOM / zend_bailout state corruption trigger
            stage = "STAGE_2_OOM_TRIGGER"
            state.current_stage = stage
            state.worker_corrupted = True
            state.add_cve("CVE-2026-109618")
            status_code = "500 Internal Server Error"
            response_body_str = (
                "<br />\n"
                "<b>Fatal error</b>:  Allowed memory size of 134217728 bytes exhausted "
                "(tried to allocate 65536 bytes) in <b>Unknown</b> on line <b>0</b><br />\n"
            )

        elif has_rce_payload or is_corrupted_followup or is_cgi_injection:
            # Stage 3: CVE-2026-109619 Stale Global State UAF / RCE Payload Execution
            stage = "STAGE_3_UAF_RCE"
            if is_oom_trigger or has_upload_progress or state.worker_corrupted:
                state.add_cve("CVE-2026-109618")
                state.add_cve("CVE-2026-109619")
                state.worker_corrupted = True
            elif is_cgi_injection:
                state.add_cve("CVE-2024-4577")
            else:
                state.add_cve("CVE-2026-109619")

            state.current_stage = stage
            full_text = f"{query}\n{body_text}\n" + "\n".join(artifacts["decoded_payloads"])
            sim_out = PHPSandboxSimulator.simulate_output(artifacts, full_text, state)
            if sim_out:
                response_body_str = sim_out
            else:
                # Realistic fallback response for binary UAF/heap-read probes
                response_body_str = (
                    "<!DOCTYPE html>\n<html><head><title>Index</title></head>"
                    "<body><!-- session_upload_progress_active --></body></html>\n"
                )

        else:
            # Stage 1: Reconnaissance / Version & Session Upload Progress Probing
            stage = "STAGE_1_RECON"
            if state.current_stage == "STAGE_1_RECON":
                state.current_stage = stage
            if has_upload_progress or is_multipart:
                state.add_cve("CVE-2026-109618")
            response_body_str = (
                "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n</head>\n"
                "<body>\n<h1>Welcome to nginx!</h1>\n"
                "<p>If you see this page, the nginx web server is successfully installed and\n"
                "working. Further configuration is required.</p>\n</body>\n</html>\n"
            )

        # Record event in timeline
        event_summary = {
            "attack_id": state.attack_id,
            "stage": stage,
            "step_index": state.step_index,
            "cves": list(state.cves_triggered),
            "method": method,
            "path": path,
            "phpsessid": state.phpsessid,
            "worker_corrupted": state.worker_corrupted,
            "extracted_commands": artifacts["commands"],
            "decoded_payloads": artifacts["decoded_payloads"],
            "dropped_files": artifacts["dropped_files"],
            "active_virtual_files": list(state.virtual_files.keys()),
            "iocs": artifacts["iocs"],
        }
        state.timeline.append(
            {
                "step": state.step_index,
                "stage": stage,
                "path": path,
                "commands": artifacts["commands"],
            }
        )

        audit_line = f"[PHP2SHELL_AUDIT] {json.dumps(event_summary, ensure_ascii=False)}"
        enriched_decoded = f"{audit_line}\n--- RAW HTTP REQUEST ---\n{raw_decoded}"

        date_str = email.utils.formatdate(usegmt=True)
        body_encoded = response_body_str.encode("utf-8")
        headers = (
            f"HTTP/1.1 {status_code}\r\n"
            f"Server: {PHPSandboxSimulator.SERVER_BANNER}\r\n"
            f"X-Powered-By: PHP/{PHPSandboxSimulator.PHP_VERSION}\r\n"
            f"Date: {date_str}\r\n"
            f"Set-Cookie: PHPSESSID={state.phpsessid}; path=/\r\n"
            f"Content-Type: text/html; charset=UTF-8\r\n"
            f"Content-Length: {len(body_encoded)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode("utf-8")

        return "http/php2shell", enriched_decoded, headers + body_encoded
