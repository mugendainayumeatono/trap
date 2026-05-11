# Trap 蜜罐系统技术文档

Trap 是一个基于 Python 开发的高性能、可扩展的蜜罐系统，旨在记录并分析在监听端口上收到的各种网络数据包，提供方便 AI 分析的数据格式。

## 1. 系统架构

系统主要由四个核心组件组成：

- **Honeypot (核心服务)**: 负责管理有状态的连接、调度协议处理器和存储模块。
- **Protocol Handlers (协议处理器)**: 负责识别流量协议，并维护握手状态以生成高度逼真的模拟响应。
- **Storage (存储模块)**: 负责将捕获的数据持久化到本地文件或 MySQL 数据库。
- **MCP Service (分析插件)**: 内置的日志分析接口，支持 HTTP REST 和 MCP SSE 协议，方便 AI 接入。

## 2. 功能特性

- **多端口监听**: 支持同时在多个端口上启动服务。
- **高级 TLS 模拟**: 实现了有状态的 TLS 1.2 握手协议。能动态解析扫描器的指纹，自适应协商所有的加密套件 (Cipher Suites)、椭圆曲线和签名算法。通过提供伪造的加密 `Finished` 数据包，成功骗取高级扫描器的完整探测载荷。
- **MCP (Model Context Protocol)**: 内置支持 MCP 协议，AI 代理可以通过 SSE 传输层或 REST API 实时调取并分析攻击日志。
- **协议自动识别**: 内置协议识别机制（目前支持 TLS, HTTP 和通用识别）。
- **灵活的存储方案**: 
    - **文件存储**: 支持自动按大小滚动日志（Rotate），线程安全。
    - **MySQL 存储**: 具备懒加载 (Lazy Init) 和自动重连能力，防宕机。
- **AI 友好**: 记录原始 Hex 数据、解码后的内容及协议类型，便于后续机器学习分析。
- **防内存泄漏**: 支持协议级的生命周期清理钩子，结合绝对会话超时，防止慢速网络攻击 (Slowloris)。

## 3. 配置说明 (环境变量)

系统通过环境变量进行配置：

| 变量名 | 描述 | 默认值 |
| :--- | :--- | :--- |
| `LISTEN_PORTS` | 监听的端口列表（逗号分隔） | `80,443,8080` |
| `STORAGE_TYPE` | 存储类型 (`file` 或 `mysql`) | `file` |
| `LOG_FILE` | 文件存储时的日志路径 | `/var/log/trap/honey.log` |
| `LOG_MAX_SIZE_MB` | 单个日志文件的最大大小（MB） | `10` |
| `TLS_CERT_PATH` | TLS 证书路径 (DER 格式) | `/app/certs/cert.der` |
| `TLS_KEY_PATH` | TLS 私钥路径 (PEM 格式) | `/app/certs/cert.key` |
| `SESSION_TIMEOUT` | 单个连接的最长存活时间（秒） | `30` |
| `MCP_HTTP_ENABLED` | 是否开启 HTTP 日志接口 | `true` |
| `MCP_SSE_ENABLED` | 是否开启 MCP SSE 服务 | `false` |
| `MCP_HTTP_PORT` | HTTP 接口端口 | `8088` |
| `MCP_SSE_PORT` | MCP SSE 服务端口 | `8089` |

## 4. 模块详细设计

### 4.1 核心逻辑 (`main.py`)
使用 `asyncio` 实现异步并发处理。引入了 `session_id` 和 `cleanup` 钩子，支持协议处理器进行多步交互。同时集成了 MCP 服务，使其随主进程一同启动。

### 4.2 协议处理 (`src/trap/handlers/`)
- **ProtocolHandler (基类)**: 定义了包含 `identify`, `handle` 和 `cleanup` 的接口。
- **TLSHandler**: 核心伪装模块。使用 `cryptography` 解析 RSA 预主密钥并派生主密钥，伪造 `Change Cipher Spec` 和 `Finished` 欺骗客户端。
- **HTTPHandler**: 识别 HTTP 请求，并返回模拟的 nginx 欢迎页面。
- **DefaultHandler**: 后备处理器。

### 4.3 MCP 服务 (`src/trap/mcp_server.py`)
提供多模式日志访问：
- **REST 模式**: 通过 `/logs` 接口提供 ISO 时间范围查询，支持 `limit` 和 `offset` 分页参数，返回包含元数据的 JSON。
- **SSE 模式**: 符合 MCP 标准的服务器端发送事件实现，提供 `fetch_logs` 工具。
- **分页与健壮性**: 具备结果上限保护（默认 100 条/次）和时区归一化逻辑。支持跨文件的日志检索（自动包含轮转后的历史日志），并返回总数和 `has_more` 标志方便批处理。

## 5. 开发与运行

### 5.1 容器启动与停止 (推荐)
项目根目录提供了 `docker-compose.yml`：
```bash
# 后台构建并启动蜜罐
docker compose up -d --build

# 查看运行日志
docker compose logs -f trap

# 查看捕获的攻击数据
tail -f logs/honey.log

# 停止并移除容器
docker compose down
```

### 5.2 自动化测试
项目包含完善的测试套件，覆盖了协议识别、握手边界检查及存储异常恢复。使用 `uv` 运行测试：
```bash
uv run pytest test/
```

### 5.3 手动验证 TLS 握手
在蜜罐启动后，可以使用 OpenSSL 客户端模拟扫描器进行握手测试：
```bash
# 测试标准的 TLS 1.2 握手 (客户端通常会在此处因等待加密验证而主动断开)
openssl s_client -connect 127.0.0.1:1080 -tls1_2 -legacy_renegotiation
```

## 6. 数据格式示例 (JSON)

```json
{
  "timestamp": "2026-04-28T06:03:31.128252",
  "sender_ip": "127.0.0.1",
  "content_hex": "16030100ba01...",
  "decoded_content": "Client Hello 0303 | Suite: c02c",
  "protocol": "tls"
}
```
