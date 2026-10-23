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


STAGE_ORDER: Dict[str, int] = {
    "STAGE_1_RECON": 1,
    "STAGE_2_OOM_TRIGGER": 2,
    "STAGE_3_UAF_RCE": 3,
    "STAGE_4_POST_EXPLOIT": 4,
}


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

    def advance_stage(self, stage: str) -> None:
        if STAGE_ORDER.get(stage, 0) >= STAGE_ORDER.get(self.current_stage, 0):
            self.current_stage = stage


class PHPAttackTracker:
    """
    Tracks multi-stage PHP2Shell (CVE-2026-109618 & CVE-2026-109619) attack chains
    across multiple HTTP requests and TCP connections by correlating client IP,
    PHPSESSID, virtual webshell paths, and corrupted worker state across proxy pools.
    """

    def __init__(self, ttl_seconds: float = 600.0):
        self.ttl_seconds = ttl_seconds
        self.by_ip: Dict[str, PHPAttackState] = {}
        self.by_sessid: Dict[str, PHPAttackState] = {}
        self.last_active_state: Optional[PHPAttackState] = None

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

        if (
            self.last_active_state is not None
            and now - self.last_active_state.last_updated > self.ttl_seconds
        ):
            self.last_active_state = None

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

    def find_existing(
        self,
        session_id: str,
        phpsessid: str = "",
        path: str = "",
        allow_worker_fallback: bool = False,
    ) -> Optional[PHPAttackState]:
        self._evict_expired()
        client_ip = self.extract_ip_from_session_id(session_id)

        if phpsessid and phpsessid in self.by_sessid:
            return self.by_sessid[phpsessid]

        if client_ip in self.by_ip:
            ip_state = self.by_ip[client_ip]
            # If caller did not supply a conflicting explicit PHPSESSID, or if this IP's
            # session was auto-generated, correlate by IP.
            if (
                not phpsessid
                or ip_state.phpsessid == phpsessid
                or phpsessid not in self.by_sessid
            ):
                return ip_state

        if path:
            for st in list(self.by_sessid.values()) + list(self.by_ip.values()):
                if path in st.virtual_files:
                    return st

        if allow_worker_fallback and not phpsessid and self.last_active_state is not None:
            if (
                self.last_active_state.worker_corrupted
                or self.last_active_state.current_stage != "STAGE_1_RECON"
            ):
                return self.last_active_state

        return None

    def get_or_create(
        self,
        session_id: str,
        phpsessid: str = "",
        path: str = "",
        allow_worker_fallback: bool = False,
    ) -> PHPAttackState:
        client_ip = self.extract_ip_from_session_id(session_id)
        state = self.find_existing(
            session_id,
            phpsessid=phpsessid,
            path=path,
            allow_worker_fallback=allow_worker_fallback,
        )

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

        self.last_active_state = state
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
    PROC_VERSION_OUTPUT = (
        "Linux version 6.8.0-45-generic (buildd@lcy02-amd64-032) "
        "(x86_64-linux-gnu-gcc-13 (Ubuntu 13.2.0-23ubuntu4) 13.2.0, "
        "GNU ld (GNU Binutils for Ubuntu) 2.42) #45-Ubuntu SMP PREEMPT_DYNAMIC "
        "Fri Aug 30 12:02:04 UTC 2024"
    )
    PROC_CPUINFO_OUTPUT = (
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\n"
        "model\t\t: 85\n"
        "model name\t: Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz\n"
        "stepping\t: 7\n"
        "microcode\t: 0x5003604\n"
        "cpu MHz\t\t: 2499.998\n"
        "cache size\t: 36608 KB\n"
        "physical id\t: 0\n"
        "siblings\t: 2\n"
        "core id\t\t: 0\n"
        "cpu cores\t: 2\n"
        "bogomips\t: 4999.99\n"
        "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch pti ssbd ibrs ibpb stibp fsgsbase tsc_adjust bmi1 avx2 smep bmi2 erms invpcid mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves arat"
    )
    ENV_OUTPUT = (
        "USER=www-data\n"
        "HOME=/var/www\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "LANG=C.UTF-8\n"
        "SHELL=/usr/sbin/nologin\n"
        "PWD=/var/www/html\n"
        "SERVER_SOFTWARE=nginx/1.18.0\n"
        "GATEWAY_INTERFACE=CGI/1.1\n"
        "DOCUMENT_ROOT=/var/www/html"
    )
    IP_ADDR_OUTPUT = (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "       valid_lft forever preferred_lft forever\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
        "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\n"
        "    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0\n"
        "       valid_lft forever preferred_lft forever"
    )
    IFCONFIG_OUTPUT = (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255\n"
        "        ether 02:42:ac:11:00:02  txqueuelen 1000  (Ethernet)\n"
        "        RX packets 14820  bytes 2145920 (2.1 MB)\n"
        "        TX packets 11204  bytes 1849210 (1.8 MB)\n\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
        "        loop  txqueuelen 1000  (Local Loopback)"
    )
    PS_AUX_OUTPUT = (
        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root           1  0.0  0.1  10840  5420 ?        Ss   Oct21   0:02 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;\n"
        "www-data      15  0.0  0.2  11280  6120 ?        S    Oct21   0:05 nginx: worker process\n"
        "root          22  0.0  0.6 218400 26400 ?        Ss   Oct21   0:04 php-fpm: master process (/etc/php/8.3/fpm/php-fpm.conf)\n"
        "www-data      23  0.1  0.8 220120 32100 ?        S    Oct21   0:12 php-fpm: pool www\n"
        "www-data      24  0.1  0.7 219800 30400 ?        S    Oct21   0:10 php-fpm: pool www\n"
        "www-data     412  0.0  0.0   2880  1520 ?        R    12:00   0:00 ps aux"
    )
    WHICH_BINARIES = {
        "curl": "/usr/bin/curl",
        "wget": "/usr/bin/wget",
        "php": "/usr/bin/php",
        "python": "/usr/bin/python3",
        "python3": "/usr/bin/python3",
        "perl": "/usr/bin/perl",
        "sh": "/usr/bin/sh",
        "bash": "/usr/bin/bash",
        "nc": "/usr/bin/nc",
        "netcat": "/usr/bin/netcat",
        "socat": "/usr/bin/socat",
        "gcc": "/usr/bin/gcc",
        "chmod": "/usr/bin/chmod",
        "base64": "/usr/bin/base64",
        "tar": "/usr/bin/tar",
        "gzip": "/usr/bin/gzip",
        "find": "/usr/bin/find",
        "id": "/usr/bin/id",
        "whoami": "/usr/bin/whoami",
        "uname": "/usr/bin/uname",
        "ip": "/usr/sbin/ip",
        "ifconfig": "/usr/sbin/ifconfig",
        "ps": "/usr/bin/ps",
        "cat": "/usr/bin/cat",
        "env": "/usr/bin/env",
    }

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
    CHR_CHAIN_RE = re.compile(
        r"chr\s*\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)(?:\s*\.\s*chr\s*\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*\))*",
        re.IGNORECASE,
    )
    SINGLE_CHR_RE = re.compile(r"chr\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*\)", re.IGNORECASE)
    HEX2BIN_RE = re.compile(
        r"(?:hex2bin\s*\(\s*['\"]([0-9a-fA-F]+)['\"]\s*\)|pack\s*\(\s*['\"]H\*['\"]\s*,\s*['\"]([0-9a-fA-F]+)['\"]\s*\))",
        re.IGNORECASE,
    )
    HEX_ESCAPE_SEQ_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){2,}")
    OCTAL_ESCAPE_SEQ_RE = re.compile(r"(?:\\[0-7]{3}){2,}")
    PHP_EXEC_RE = re.compile(
        r"(?:\(\s*)?['\"]?(?:system|exec|shell_exec|passthru|popen|proc_open)['\"]?(?:\s*\))?\s*\(\s*(?:'([^']*)'|\"([^\"]*)\")\s*\)",
        re.IGNORECASE,
    )
    BACKTICK_RE = re.compile(r"`([^`\r\n]{1,512})`")
    DOUBLE_QUOTE_INTERP_RE = re.compile(
        r"\{\$\{([^}]+)\}\}|\$\{([^}]+)\}",
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
        r"cat\s+/(?:etc|proc)/[a-zA-Z0-9_./-]+|echo\s+[^\r\n;&|`\"]+|printf\s+[^\r\n;&|`\"]+|"
        r"curl\s+[^\r\n;&|`]+|wget\s+[^\r\n;&|`]+|php\s+-[a-zA-Z]+|"
        r"env|printenv|ifconfig(?:\s+-a)?|ip\s+(?:addr(?:ess)?|a|route|link)(?:\s+show)?|"
        r"ps(?:\s+(?:aux|-ef|-aux|-e|-A))?|"
        r"which\s+[a-zA-Z0-9_.\-]+(?:\s+[a-zA-Z0-9_.\-]+)*|"
        r"command\s+-v\s+[a-zA-Z0-9_.\-]+(?:\s+[a-zA-Z0-9_.\-]+)*))\b(?!\s*:)",
        re.IGNORECASE,
    )

    STANDARD_BENIGN_HEADERS = {
        "host",
        "connection",
        "content-length",
        "content-type",
        "accept",
        "accept-encoding",
        "cache-control",
        "pragma",
        "upgrade-insecure-requests",
        "date",
    }

    @classmethod
    def deobfuscate_php_expressions(cls, text: str) -> List[str]:
        """
        Decodes PHP obfuscation techniques including:
        - chr(115).chr(121)... concatenation
        - hexescape sequences (\\x73\\x79\\x73\\x74\\x65\\x6d) and octal escapes (\\163\\171...)
        - hex2bin('...') and pack('H*', '...')
        - String literal concatenation ('sys'.'tem')
        - Variable function assignment ($f='system'; $f('id'))
        - Double-quoted PHP variable/command interpolation ("${system('id')}", "{${`id`}}")
        """
        results: List[str] = []
        transformed = text

        # 1. Decode hex2bin / pack('H*', ...)
        def _replace_hex2bin(m: re.Match) -> str:
            hex_str = m.group(1) or m.group(2) or ""
            try:
                dec = bytes.fromhex(hex_str).decode("utf-8", errors="replace")
                return f"'{dec}'"
            except Exception:
                return m.group(0)

        transformed = cls.HEX2BIN_RE.sub(_replace_hex2bin, transformed)

        # 2. Decode chr() chains
        def _replace_chr_chain(m: re.Match) -> str:
            chain_str = m.group(0)
            chars = []
            for num_str in cls.SINGLE_CHR_RE.findall(chain_str):
                try:
                    val = int(num_str, 0)
                    if 0 <= val <= 0x10FFFF:
                        chars.append(chr(val))
                except Exception:
                    pass
            if chars:
                return "'" + "".join(chars) + "'"
            return chain_str

        transformed = cls.CHR_CHAIN_RE.sub(_replace_chr_chain, transformed)

        # 3. Decode \xHH hex escape sequences
        def _replace_hex_escapes(m: re.Match) -> str:
            seq = m.group(0)
            try:
                raw_hex = seq.replace("\\x", "").replace("\\X", "")
                return bytes.fromhex(raw_hex).decode("utf-8", errors="replace")
            except Exception:
                return seq

        transformed = cls.HEX_ESCAPE_SEQ_RE.sub(_replace_hex_escapes, transformed)

        # 4. Decode octal escape sequences \163\171...
        def _replace_octal_escapes(m: re.Match) -> str:
            seq = m.group(0)
            try:
                oct_parts = [p for p in seq.split("\\") if p]
                b = bytes(int(p, 8) & 0xFF for p in oct_parts)
                return b.decode("utf-8", errors="replace")
            except Exception:
                return seq

        transformed = cls.OCTAL_ESCAPE_SEQ_RE.sub(_replace_octal_escapes, transformed)

        # 5. Collapse adjacent PHP string concatenations: 'sys' . 'tem' -> 'system'
        for _ in range(3):
            transformed = re.sub(
                r"'([^'\r\n]*)'\s*\.\s*'([^'\r\n]*)'", r"'\1\2'", transformed
            )
            transformed = re.sub(
                r'"([^"\r\n]*)"\s*\.\s*"([^"\r\n]*)"', r'"\1\2"', transformed
            )

        # 6. Resolve simple variable function calls: $f = 'system'; $f('id') -> system('id')
        var_bindings: Dict[str, str] = {}
        for var_name, val1, val2 in re.findall(
            r"\$([a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff]*)\s*=\s*(?:'([^'\r\n]+)'|\"([^\"\r\n]+)\")\s*;",
            transformed,
        ):
            var_bindings[var_name] = val1 or val2
        for var_name, func_val in var_bindings.items():
            transformed = re.sub(
                rf"\${re.escape(var_name)}\s*\(",
                f"{func_val}(",
                transformed,
            )

        # 7. Normalize parenthesized or quoted function invocation: ('system')('id') or "system"("id") -> system('id')
        transformed = re.sub(
            r"(?:\(\s*)?['\"](system|exec|shell_exec|passthru|popen|proc_open|eval|assert)['\"](?:\s*\))?\s*\(",
            r"\1(",
            transformed,
            flags=re.IGNORECASE,
        )

        if transformed != text:
            results.append(transformed)

        # 8. Extract inner expressions from PHP double-quoted interpolation: "${system('id')}" or "{${`id`}}"
        for m in cls.DOUBLE_QUOTE_INTERP_RE.finditer(transformed):
            inner = (m.group(1) or m.group(2) or "").strip()
            if inner and inner not in results:
                results.append(inner)

        return results

    @classmethod
    def decode_nested_base64(cls, text: str) -> List[str]:
        decoded_items: List[str] = []
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
    def _extract_header_and_cookie_candidates(cls, headers_text: str) -> Tuple[List[str], List[str]]:
        """
        Extracts suspicious or custom header values and Cookie key/value pairs so that
        obfuscated, base64, hex, or binary payloads carried in headers (e.g. X-Requested-With,
        Cookie, custom X-* headers) are decoded and inspected.
        Returns (text_Fragments, decoded_payloads).
        """
        fragments: List[str] = []
        decoded_payloads: List[str] = []

        lines = headers_text.splitlines()
        for line in lines[1:]:
            if ":" not in line:
                continue
            h_name, h_val = line.split(":", 1)
            h_name_clean = h_name.strip().lower()
            h_val_clean = h_val.strip()
            if not h_val_clean:
                continue

            if h_name_clean == "cookie":
                for pair in h_val_clean.split(";"):
                    pair = pair.strip()
                    if not pair:
                        continue
                    if "=" in pair:
                        c_key, c_val = pair.split("=", 1)
                        c_key = c_key.strip()
                        c_val = c_val.strip().strip("'\"")
                    else:
                        c_key, c_val = "", pair
                    if c_key.upper() == "PHPSESSID":
                        continue
                    unq_exact = urllib.parse.unquote(c_val)
                    unq_val = urllib.parse.unquote_plus(c_val)
                    fragments.append(f"{c_key}={unq_val}" if c_key else unq_val)
                    cls._try_decode_blob(unq_exact, decoded_payloads, is_custom_carrier=True)
                    if unq_val != unq_exact:
                        cls._try_decode_blob(unq_val, decoded_payloads, is_custom_carrier=True)
            elif h_name_clean not in cls.STANDARD_BENIGN_HEADERS:
                # Ignore standard XMLHttpRequest unless modified
                if h_name_clean == "x-requested-with" and h_val_clean.lower() == "xmlhttprequest":
                    continue
                unq_exact = urllib.parse.unquote(h_val_clean)
                unq_val = urllib.parse.unquote_plus(h_val_clean)
                fragments.append(unq_val)
                is_custom = h_name_clean.startswith("x-") or h_name_clean in (
                    "accept-charset",
                    "authorization",
                    "referer",
                )
                cls._try_decode_blob(unq_exact, decoded_payloads, is_custom_carrier=is_custom)
                if unq_val != unq_exact:
                    cls._try_decode_blob(unq_val, decoded_payloads, is_custom_carrier=is_custom)

        return fragments, decoded_payloads

    @classmethod
    def _try_decode_blob(
        cls, candidate: str, decoded_payloads: List[str], is_custom_carrier: bool = False
    ) -> None:
        cleaned = candidate.strip()
        if not cleaned:
            return

        # Check if candidate contains hex escapes, chr(), PHP tags, or shell execution
        for deob in cls.deobfuscate_php_expressions(cleaned):
            if deob not in decoded_payloads:
                decoded_payloads.append(deob)

        # Check for raw base64 token (either whole string or embedded after =/:)
        tokens = [cleaned]
        for sub_tok in re.findall(r"[A-Za-z0-9+/]{12,}={0,2}", cleaned):
            if sub_tok not in tokens:
                tokens.append(sub_tok)

        for tok in tokens:
            if len(tok) >= 8 and len(tok) % 4 == 0 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", tok):
                try:
                    raw_bytes = base64.b64decode(tok, validate=True)
                    if not raw_bytes:
                        continue
                    text_dec = raw_bytes.decode("utf-8", errors="replace")
                    if (
                        any(
                            kw in text_dec.lower()
                            for kw in (
                                "<?php",
                                "system",
                                "exec",
                                "passthru",
                                "eval",
                                "base64_decode",
                                "whoami",
                                "uname",
                                "/etc/",
                                "/proc/",
                                "/bin/",
                                "cmd",
                                "echo ",
                                "curl ",
                                "wget ",
                                "chr(",
                            )
                        )
                        or (is_custom_carrier and raw_bytes.count(b"\x00") >= 2)
                        or (is_custom_carrier and b"\x7f" in raw_bytes)
                    ):
                        if "\ufffd" in text_dec or b"\x00" in raw_bytes:
                            marker = f"[BINARY_B64:{raw_bytes[:32].hex()}]"
                            if marker not in decoded_payloads:
                                decoded_payloads.append(marker)
                        elif text_dec not in decoded_payloads:
                            decoded_payloads.append(text_dec)
                except Exception:
                    pass

        # If a custom carrier (e.g. X-Requested-With or custom Cookie) carries raw non-ASCII/null/hex-pointer data
        if is_custom_carrier:
            if (
                "\x00" in cleaned
                or "\ufffd" in cleaned
                or re.search(r"0x7f[0-9a-fA-F]{6,}", cleaned, re.I)
            ):
                marker = f"[CUSTOM_HEADER_BINARY:{cleaned[:64]}]"
                if marker not in decoded_payloads:
                    decoded_payloads.append(marker)

    @classmethod
    def extract_artifacts(
        cls,
        request_path: str,
        query_string: str,
        headers_text: str,
        body_text: str,
        body_bytes: bytes = b"",
    ) -> Dict[str, object]:
        unquoted_query = urllib.parse.unquote_plus(query_string)
        unquoted_body = urllib.parse.unquote_plus(body_text)
        header_fragments, header_decoded = cls._extract_header_and_cookie_candidates(headers_text)
        headers_joined = "\n".join(header_fragments)

        combined = f"{unquoted_query}\n{body_text}\n{unquoted_body}\n{headers_joined}"

        decoded_payloads: List[str] = list(header_decoded)
        for b64_item in cls.decode_nested_base64(combined):
            if b64_item not in decoded_payloads:
                decoded_payloads.append(b64_item)

        # Also check if form/query/cookie parameters like cmd= or c= or 0= carry raw base64 or commands
        param_regex = re.compile(
            r"(?:^|[&?;\r\n\s])(?:cmd|c|exec|command|e|0|payload|code|data)=([^&;\r\n]+)",
            re.IGNORECASE,
        )
        for val in param_regex.findall(f"{query_string}\n{body_text}\n{headers_joined}"):
            unq = urllib.parse.unquote_plus(val).strip()
            if unq and unq not in decoded_payloads:
                decoded_payloads.append(unq)
            if len(unq) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=]+", unq):
                try:
                    b64_dec = base64.b64decode(unq).decode("utf-8", errors="replace")
                    if b64_dec and b64_dec.isprintable() and b64_dec not in decoded_payloads:
                        decoded_payloads.append(b64_dec)
                except Exception:
                    pass

        # Deobfuscate hex escapes, chr() concatenations, variable functions, and ${...} interpolations
        for source_text in [combined] + list(decoded_payloads):
            for deob in cls.deobfuscate_php_expressions(source_text):
                if deob not in decoded_payloads:
                    decoded_payloads.append(deob)
                for nested_b64 in cls.decode_nested_base64(deob):
                    if nested_b64 not in decoded_payloads:
                        decoded_payloads.append(nested_b64)

        all_inspection_text = combined + "\n" + "\n".join(decoded_payloads)

        # Extract PHP snippets
        php_tags = re.findall(r"<\?(?:php|=).*?\?>", all_inspection_text, re.IGNORECASE | re.DOTALL)
        for tag in php_tags:
            if tag not in decoded_payloads:
                decoded_payloads.append(tag)

        # Extract commands inside PHP execution functions (system, exec, passthru, shell_exec, etc.)
        commands: List[str] = []
        for g1, g2 in cls.PHP_EXEC_RE.findall(all_inspection_text):
            cmd = g1 or g2
            for sub_cmd in [c.strip() for c in re.split(r"(?:;|&&|\|\||\n)", cmd) if c.strip()]:
                if sub_cmd not in commands:
                    commands.append(sub_cmd)

        # Extract commands inside PHP backticks (`id`, <?php echo `id`; ?>, "${`id`}")
        for bt_cmd in cls.BACKTICK_RE.findall(all_inspection_text):
            bt_clean = bt_cmd.strip()
            if bt_clean and bt_clean not in decoded_payloads:
                decoded_payloads.append(f"`{bt_clean}`")
            for sub_cmd in [c.strip() for c in re.split(r"(?:;|&&|\|\||\n)", bt_clean) if c.strip()]:
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
            norm_path = re.sub(
                r"^(?:/var/www/html/|/var/www/|/usr/share/nginx/html/|\./)+", "", fname.strip()
            )
            clean_name = "/" + norm_path.lstrip("/")
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
            "all_inspection_text": all_inspection_text,
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
        for md5_arg in re.findall(
            r"md5\s*\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)", full_inspection_text, re.I
        ):
            outputs.append(hashlib.md5(md5_arg.encode("utf-8")).hexdigest())

        # Check for PHP echo/print string literals (outside shell commands and backticks)
        for php_echo in re.findall(
            r"(?:<\?php|;)\s*(?:echo|print)\s+['\"]([^'\"`$]+)['\"]\s*;",
            full_inspection_text,
            re.IGNORECASE,
        ):
            if php_echo not in outputs:
                outputs.append(php_echo)

        commands: List[str] = artifacts.get("commands", [])  # type: ignore
        for cmd in commands:
            cmd_clean = cmd.strip()
            cmd_lower = cmd_clean.lower()
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
            elif cmd_lower.startswith("cat /proc/version"):
                outputs.append(cls.PROC_VERSION_OUTPUT)
            elif cmd_lower.startswith("cat /proc/cpuinfo"):
                outputs.append(cls.PROC_CPUINFO_OUTPUT)
            elif cmd_lower in ("env", "printenv"):
                outputs.append(cls.ENV_OUTPUT)
            elif cmd_lower.startswith("ip addr") or cmd_lower.startswith("ip a") or cmd_lower.startswith("ip link"):
                outputs.append(cls.IP_ADDR_OUTPUT)
            elif cmd_lower.startswith("ifconfig"):
                outputs.append(cls.IFCONFIG_OUTPUT)
            elif cmd_lower.startswith("ps"):
                outputs.append(cls.PS_AUX_OUTPUT)
            elif cmd_lower.startswith("which ") or cmd_lower.startswith("command -v "):
                arg_part = re.sub(r"^(?:which|command\s+-v)\s+", "", cmd_clean, flags=re.I).strip()
                resolved = []
                for bin_name in arg_part.split():
                    b_clean = bin_name.strip("'\";|&")
                    if not b_clean or b_clean.startswith("-"):
                        continue
                    resolved.append(cls.WHICH_BINARIES.get(b_clean.lower(), f"/usr/bin/{b_clean}"))
                if resolved:
                    outputs.append("\n".join(resolved))
            elif cmd_lower.startswith("php -v"):
                outputs.append(
                    f"PHP {cls.PHP_VERSION} (cli) (built: Oct  1 2026 10:12:00) (NTS)\n"
                    f"Copyright (c) The PHP Group\n"
                    f"Zend Engine v4.3.34, Copyright (c) Zend Technologies"
                )
            elif cmd_lower.startswith("echo ") or cmd_lower.startswith("printf "):
                if ">" not in cmd_clean and "`" not in cmd_clean:
                    arg = re.sub(
                        r"^(?:echo|printf)\s+(?:-[neE]+\s+)?", "", cmd_clean, flags=re.I
                    ).strip()
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

    NEXT_HTTP_REQ_RE = re.compile(
        rb"(?:\r?\n|^)((?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/1\.[01]\r?\n)"
    )

    def __init__(self, tracker: Optional[PHPAttackTracker] = None):
        self.tracker = tracker or PHPAttackTracker()
        self.buffers: Dict[str, HTTPStreamBuffer] = {}

    def cleanup_session(self, session_id: str) -> Optional[Tuple[str, str, bytes, bytes]]:
        buf = self.buffers.pop(session_id, None)
        if buf and buf.data:
            raw_bytes = bytes(buf.data)
            # Ensure state transitions (e.g., OOM worker corruption) and audit logs are recorded
            # even if the attacker disconnects or times out after sending a truncated payload.
            try:
                res = self._analyze_and_respond(raw_bytes, session_id, is_cleanup=True)
                if res is not None:
                    proto, decoded, resp = res
                    return proto, decoded, resp, raw_bytes
            except Exception:
                pass
        return None

    def is_buffering(self, session_id: str) -> bool:
        return bool(session_id and session_id in self.buffers)

    def _split_pipelined_requests(self, raw_stream: bytes) -> List[bytes]:
        """
        Splits a raw TCP byte buffer containing multiple pipelined / sticky HTTP requests
        into individual HTTP request byte slices.
        """
        requests: List[bytes] = []
        remaining = raw_stream

        while remaining:
            stripped = remaining.lstrip(b"\r\n")
            if not stripped:
                break
            leading_ws_len = len(remaining) - len(stripped)
            if leading_ws_len > 0:
                remaining = stripped

            sep_idx = remaining.find(b"\r\n\r\n")
            sep_len = 4
            if sep_idx == -1:
                sep_idx = remaining.find(b"\n\n")
                sep_len = 2

            if sep_idx == -1:
                requests.append(remaining)
                break

            headers_bytes = remaining[:sep_idx]
            body_start = sep_idx + sep_len
            rest = remaining[body_start:]
            headers_str = headers_bytes.decode("latin-1", errors="ignore")

            first_line = headers_str.splitlines()[0] if headers_str else ""
            method = first_line.split(" ", 1)[0].upper() if first_line else "GET"

            cl_match = re.search(r"(?i)(?:^|[\r\n])Content-Length:\s*(\d+)", headers_str)
            content_length = int(cl_match.group(1)) if cl_match else None

            b_match = re.search(
                r'(?i)Content-Type:\s*multipart/form-data\s*;[^\r\n]*boundary=["\']?([^"\'\s;\r\n]+)',
                headers_str,
            )
            boundary = b_match.group(1).encode("latin-1", errors="ignore") if b_match else None

            split_offset_in_rest: Optional[int] = None

            # 1. Exact Content-Length boundary followed by another HTTP request line
            if content_length is not None and 0 <= content_length < len(rest):
                candidate_after = rest[content_length:].lstrip(b"\r\n")
                if self.NEXT_HTTP_REQ_RE.match(candidate_after):
                    ws_len = len(rest[content_length:]) - len(candidate_after)
                    split_offset_in_rest = content_length + ws_len

            # 2. Multipart closing boundary followed by another HTTP request line
            if split_offset_in_rest is None and boundary:
                closing = b"--" + boundary + b"--"
                c_idx = rest.find(closing)
                if c_idx != -1:
                    after_c = c_idx + len(closing)
                    if rest[after_c : after_c + 2] == b"\r\n":
                        after_c += 2
                    elif rest[after_c : after_c + 1] == b"\n":
                        after_c += 1
                    candidate_after = rest[after_c:].lstrip(b"\r\n")
                    if candidate_after and self.NEXT_HTTP_REQ_RE.match(candidate_after):
                        ws_len = len(rest[after_c:]) - len(candidate_after)
                        split_offset_in_rest = after_c + ws_len

            # 3. Bodyless methods (GET/HEAD/OPTIONS/DELETE) or truncated/inflated Content-Length
            # where another full HTTP/1.x request line appears inside `rest`
            if split_offset_in_rest is None and rest:
                if content_length is None and method in ("GET", "HEAD", "OPTIONS", "DELETE"):
                    candidate_after = rest.lstrip(b"\r\n")
                    if self.NEXT_HTTP_REQ_RE.match(candidate_after):
                        split_offset_in_rest = len(rest) - len(candidate_after)
                elif content_length is None or content_length > len(rest):
                    m_next = self.NEXT_HTTP_REQ_RE.search(rest)
                    if m_next:
                        split_offset_in_rest = m_next.start(1)

            if split_offset_in_rest is not None:
                req_end = body_start + split_offset_in_rest
                requests.append(remaining[:req_end])
                remaining = remaining[req_end:]
            else:
                requests.append(remaining)
                break

        return requests if requests else [raw_stream]

    def process_chunk(
        self, data: bytes, session_id: str = ""
    ) -> Optional[Tuple[str, str, bytes]]:
        """
        Handles incoming HTTP data (potentially across multiple TCP reads or pipelined requests).
        Returns (protocol, decoded_content, response_bytes) if handled as a PHP/PHP2Shell
        interaction or buffered fragment, or None if it is a standard non-PHP HTTP request.
        """
        if session_id and session_id in self.buffers:
            buf = self.buffers[session_id]
            buf.data.extend(data)
            buf.chunks_count += 1
            segments = self._split_pipelined_requests(bytes(buf.data))
            if len(segments) == 1 and self._needs_more_chunks(
                segments[0], len(data), buf.chunks_count
            ):
                raw_preview = data.decode("utf-8", errors="replace")
                return (
                    "http/php2shell",
                    f"[PHP2SHELL_FRAGMENT chunk={buf.chunks_count} buffered={len(buf.data)}]\n{raw_preview}",
                    b"",
                )
            del self.buffers[session_id]
            return self._process_segments(segments, len(data), session_id)

        # First chunk on this connection: split any pipelined requests first
        segments = self._split_pipelined_requests(data)
        if len(segments) == 1 and session_id and self._should_start_buffering(segments[0], len(data)):
            buf = HTTPStreamBuffer()
            buf.data.extend(segments[0])
            buf.chunks_count = 1
            self.buffers[session_id] = buf
            raw_preview = data.decode("utf-8", errors="replace")
            return (
                "http/php2shell",
                f"[PHP2SHELL_FRAGMENT chunk=1 buffered={len(buf.data)}]\n{raw_preview}",
                b"",
            )

        return self._process_segments(segments, len(data), session_id)

    def _process_segments(
        self, segments: List[bytes], last_read_len: int, session_id: str
    ) -> Optional[Tuple[str, str, bytes]]:
        if len(segments) == 1:
            return self._analyze_and_respond(segments[0], session_id)

        # Multiple pipelined requests in the same stream buffer
        complete_segments = segments[:-1]
        last_segment = segments[-1]
        if session_id and self._should_start_buffering(last_segment, last_read_len):
            buf = HTTPStreamBuffer()
            buf.data.extend(last_segment)
            buf.chunks_count = 1
            self.buffers[session_id] = buf
        else:
            complete_segments.append(last_segment)

        results: List[Tuple[str, str, bytes]] = []
        for seg in complete_segments:
            res = self._analyze_and_respond(seg, session_id)
            if res is not None:
                results.append(res)

        if not results:
            return None
        if len(results) == 1:
            return results[0]

        # Combine pipelined results while preserving valid [PHP2SHELL_AUDIT] JSON on line 1
        combined_resp = b"".join(r[2] for r in results)
        metas = []
        for _, dec, _ in results:
            if dec.startswith("[PHP2SHELL_AUDIT] "):
                first_line = dec.split("\n", 1)[0]
                try:
                    metas.append(json.loads(first_line[len("[PHP2SHELL_AUDIT] ") :].strip()))
                except Exception:
                    pass

        if metas:
            merged_meta = dict(metas[-1])
            # Pick highest stage reached across the pipelined batch
            best_stage = max(
                (m.get("stage", "STAGE_1_RECON") for m in metas),
                key=lambda s: STAGE_ORDER.get(s, 0),
            )
            merged_meta["stage"] = best_stage
            merged_meta["pipelined_count"] = len(metas)
            merged_meta["pipelined_stages"] = [m.get("stage") for m in metas]
            for list_key in ("cves", "extracted_commands", "decoded_payloads", "dropped_files", "iocs"):
                acc: List[str] = []
                for m in metas:
                    for item in m.get(list_key, []):
                        if item not in acc:
                            acc.append(item)
                merged_meta[list_key] = acc

            top_audit = f"[PHP2SHELL_AUDIT] {json.dumps(merged_meta, ensure_ascii=False)}"
            sub_audits = "\n=== PIPELINED REQUEST ===\n".join(r[1] for r in results)
            return "http/php2shell", f"{top_audit}\n{sub_audits}", combined_resp

        return "http/php2shell", "\n".join(r[1] for r in results), combined_resp

    def _should_start_buffering(self, data: bytes, last_read_len: int) -> bool:
        stripped = data.lstrip(b"\r\n")
        if not (stripped.startswith(b"POST ") or stripped.startswith(b"PUT ")):
            return False
        return self._needs_more_chunks(data, last_read_len, 1)

    def _needs_more_chunks(
        self, accumulated: bytes, last_read_len: int, chunks_count: int
    ) -> bool:
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

        cl_match = re.search(r"(?i)(?:^|[\r\n])Content-Length:\s*(\d+)", headers_str)
        content_length = int(cl_match.group(1)) if cl_match else None

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

        body_text = body_bytes.decode("utf-8", errors="replace")
        has_upload_progress = (
            "PHP_SESSION_UPLOAD_PROGRESS" in body_text or "upload_progress_" in body_text
        )

        # If the partial body already exhibits explicit OOM / heap corruption features
        # (e.g., serialized object injection, null-byte pointer spray, deep array brackets)
        # and the socket read wasn't full, process immediately without hanging.
        if len(body_bytes) > 0 and last_read_len < 4096:
            if (
                body_bytes.count(b"\x00") >= 4
                or re.search(r"(?:\||^)(?:O|C|a|s):\d+:", body_text)
                or re.search(r"(\[[^\]]*\]\s*){5,}", body_text)
            ):
                return False

        if content_length is not None:
            if content_length == 0:
                return False
            # For declared Content-Length >= 1024 (including medium fake Content-Length like 16KB
            # as well as huge 128MB OOM triggers):
            # Wait if body is still empty (headers arrived in their own packet), or if the sender
            # is actively filling 4096-byte TCP reads. If body_bytes > 0 and last_read_len < 4096,
            # the sender sent a truncated/short body and stopped—process immediately!
            if content_length >= 1024:
                if len(body_bytes) == 0:
                    return True
                if len(body_bytes) >= content_length:
                    return False
                return last_read_len >= 4096

            # Small Content-Length (< 1024): wait until declared body bytes arrive
            if len(body_bytes) < content_length:
                return True
            return False

        # No Content-Length, but multipart/form-data without closing boundary yet
        if boundary:
            if len(body_bytes) > 0 and last_read_len < 4096 and has_upload_progress:
                return False
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
        # 1. Cookie header (supports underscores, hyphens, dots, colons, URL-encoding, etc.)
        m_cookie = re.search(
            r'(?i)Cookie:[^\r\n]*\bPHPSESSID=["\']?([A-Za-z0-9_,.:~%+=-]{1,128})["\']?',
            headers_text,
        )
        if m_cookie:
            return urllib.parse.unquote(m_cookie.group(1))
        # 2. Multipart form field name="PHPSESSID" (CVE-2026-109618 use_only_cookies bypass)
        m_form = re.search(
            r'name=["\']PHPSESSID["\'][^\r\n]*\r?\n\r?\n([^\r\n]+)',
            body_text,
            re.IGNORECASE,
        )
        if m_form:
            val = m_form.group(1).strip()
            if val and not val.startswith("--"):
                return val
        # 3. Query string or URL-encoded body
        m_param = re.search(
            r"(?:^|[&?\s])PHPSESSID=([A-Za-z0-9_,.:~%+-]{1,128})", f"{query}&{body_text}"
        )
        if m_param:
            return urllib.parse.unquote(m_param.group(1))
        return ""

    def _is_oom_corruption_trigger(
        self,
        headers_text: str,
        body_bytes: bytes,
        body_text: str,
        has_upload_progress: bool,
        is_cleanup: bool = False,
    ) -> bool:
        """
        Detects CVE-2026-109618 Out-of-Memory (OOM) / zend_bailout() trigger patterns:
        1. Oversized Content-Length (>= 1MB) or truncated medium Content-Length without closing boundary
        2. Upload progress with malformed/unclosed multipart boundary or truncated part
        3. Deeply nested array variables (e.g., a[b][c][d][e]...) or excessive multipart parts
        4. High-density heap-feng-shui padding or binary fake zval/pointer spray (0x00007f...)
        5. Session serialization injection via PHP_SESSION_UPLOAD_PROGRESS (|O:, |a:, etc.)
        """
        cl_match = re.search(r"(?i)(?:^|[\r\n])Content-Length:\s*(\d+)", headers_text)
        declared_cl = int(cl_match.group(1)) if cl_match else None
        if declared_cl is not None and declared_cl >= 1048576:
            return True

        b_match = re.search(
            r'(?i)Content-Type:\s*multipart/form-data\s*;[^\r\n]*boundary=["\']?([^"\'\s;\r\n]+)',
            headers_text,
        )
        if b_match:
            boundary_bytes = b_match.group(1).encode("latin-1", errors="ignore")
            has_closing = (b"--" + boundary_bytes + b"--") in body_bytes
            # Malformed/unclosed multipart with upload progress, truncated Content-Length, or abrupt disconnect
            if not has_closing and len(body_bytes) > 0:
                if (
                    has_upload_progress
                    or is_cleanup
                    or (declared_cl is not None and declared_cl > len(body_bytes))
                ):
                    return True
            # Excessive multipart parts (> 10 parts)
            if body_bytes.count(b"--" + boundary_bytes) > 10:
                return True

        # Abrupt disconnect before Content-Length was satisfied on a POST/PUT request
        if is_cleanup and declared_cl is not None and 0 < len(body_bytes) < declared_cl:
            return True

        # Deeply nested array brackets
        if re.search(r"(\[[^\]]*\]\s*){5,}", body_text):
            return True

        # Large padding (>= 2KB) with upload_progress or multipart
        if len(body_bytes) >= 2048 and (has_upload_progress or b_match is not None):
            return True

        # Non-ASCII binary ROP / fake pointer patterns (\x7f, \x00\x00\x00) inside multipart or upload progress
        non_ascii_nulls = body_bytes.count(b"\x00")
        if non_ascii_nulls >= 8 and (has_upload_progress or b_match is not None):
            return True

        # Serialized object/array injection inside PHP_SESSION_UPLOAD_PROGRESS
        if has_upload_progress and re.search(r"(?:\||^)(?:O|C|a|s):\d+:", body_text):
            return True

        return False

    def _has_suspicious_header_or_binary_payload(
        self, headers_text: str, query: str, body_bytes: bytes, body_text: str
    ) -> bool:
        """
        Detects binary or obfuscated PHP/UAF payloads delivered to pseudo-static (Rewrite) routes
        without .php extensions (e.g. POST /api/upload, POST /login) via custom headers, cookies,
        or request body.
        """
        # Binary null bytes or 64-bit userland pointer spray in body or URL-encoded %00/%7f
        if body_bytes.count(b"\x00") >= 2 or (b"\x7f" in body_bytes and b"\x00" in body_bytes):
            return True
        if re.search(r"%00|%7f", f"{query}\n{headers_text}\n{body_text}", re.I):
            return True

        # Hex escapes (\x41\x42...), chr(...), serialized PHP objects, php:// wrappers, or superglobals
        combined_check = f"{query}\n{headers_text}\n{body_text}"
        if re.search(
            r"(?:\\x[0-9a-fA-F]{2}){2,}|chr\s*\(\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)|"
            r"hex2bin\s*\(|base64_decode\s*\(|(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_SERVER)|"
            r"php://(?:input|filter)|(?:^|[|;&\s\"'=])(?:O|C):\d+:\"[A-Za-z0-9_\\]+\":\d+:",
            combined_check,
            re.IGNORECASE,
        ):
            return True

        return False

    def _analyze_and_respond(
        self, data: bytes, session_id: str, is_cleanup: bool = False
    ) -> Optional[Tuple[str, str, bytes]]:
        method, path, query, headers_text, body_bytes = self._parse_http_request(data)
        body_text = body_bytes.decode("utf-8", errors="replace")
        raw_decoded = data.decode("utf-8", errors="replace")

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

        artifacts = PHPSandboxSimulator.extract_artifacts(
            path, query, headers_text, body_text, body_bytes
        )
        all_inspection_text = str(artifacts.get("all_inspection_text", f"{query}\n{body_text}"))

        has_suspicious_carrier = self._has_suspicious_header_or_binary_payload(
            headers_text, query, body_bytes, body_text
        )
        has_rce_payload = bool(
            artifacts["commands"]
            or artifacts["decoded_payloads"]
            or artifacts["dropped_files"]
            or re.search(r"phpinfo\s*\(", all_inspection_text, re.I)
            or has_suspicious_carrier
        )
        is_oom_trigger = self._is_oom_corruption_trigger(
            headers_text, body_bytes, body_text, has_upload_progress, is_cleanup=is_cleanup
        )

        # Allow fallback correlation to recently corrupted worker state when a follow-up request
        # arrives from a rotated proxy IP on a pseudo-static route without PHPSESSID.
        allow_fallback = bool(
            has_rce_payload
            or is_oom_trigger
            or has_upload_progress
            or is_php_path
            or method in ("POST", "PUT")
        )
        existing_state = self.tracker.find_existing(
            session_id,
            phpsessid=phpsessid,
            path=path,
            allow_worker_fallback=allow_fallback,
        )

        is_virtual_webshell = bool(
            existing_state and path in existing_state.virtual_files
        )
        is_corrupted_followup = bool(
            existing_state
            and existing_state.worker_corrupted
            and (
                has_rce_payload
                or is_php_path
                or bool(phpsessid)
                or method in ("POST", "PUT")
            )
        )

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

        state = self.tracker.get_or_create(
            session_id,
            phpsessid=phpsessid,
            path=path,
            allow_worker_fallback=allow_fallback,
        )
        state.step_index += 1

        # Stage classification & CVE attribution
        status_code = "200 OK"
        response_body_str = ""

        is_uaf_consumer_probe = bool(
            "uaf_trigger" in all_inspection_text.lower()
            or (has_suspicious_carrier and not artifacts["commands"])
        )

        if is_virtual_webshell or (
            state.current_stage in ("STAGE_3_UAF_RCE", "STAGE_4_POST_EXPLOIT")
            and has_rce_payload
            and not is_oom_trigger
            and not has_upload_progress
            and not is_uaf_consumer_probe
            and not artifacts["dropped_files"]
        ):
            # Stage 4: Post-Exploitation / Webshell interaction
            stage = "STAGE_4_POST_EXPLOIT"
            state.advance_stage(stage)
            if not state.cves_triggered:
                state.add_cve("CVE-2026-109618")
                state.add_cve("CVE-2026-109619")
            sim_out = PHPSandboxSimulator.simulate_output(artifacts, all_inspection_text, state)
            response_body_str = sim_out if sim_out else "OK\n"

        elif is_oom_trigger and not (
            artifacts["commands"]
            or artifacts["dropped_files"]
            or re.search(r"phpinfo\s*\(", all_inspection_text, re.I)
        ):
            # Stage 2: Pure CVE-2026-109618 OOM / zend_bailout state corruption trigger
            stage = "STAGE_2_OOM_TRIGGER"
            state.advance_stage(stage)
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

            state.advance_stage(stage)
            sim_out = PHPSandboxSimulator.simulate_output(artifacts, all_inspection_text, state)
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
            state.advance_stage(stage)
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
            "current_stage": state.current_stage,
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
