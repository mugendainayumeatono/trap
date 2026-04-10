# Trap 蜜罐系统技术文档

Trap 是一个基于 Python 开发的高性能、可扩展的蜜罐系统，旨在记录并分析在监听端口上收到的各种网络数据包，提供方便 AI 分析的数据格式。

## 1. 系统架构

系统主要由三个核心组件组成：

- **Honeypot (核心服务)**: 负责管理连接、调度协议处理器和存储模块。
- **Protocol Handlers (协议处理器)**: 负责识别流量协议并生成模拟响应。
- **Storage (存储模块)**: 负责将捕获的数据持久化到本地文件或 MySQL 数据库。

## 2. 功能特性

- **多端口监听**: 支持同时在多个端口上启动服务。
- **协议自动识别**: 内置简单的协议识别机制（目前支持 HTTP 和通用识别）。
- **灵活的存储方案**: 
    - **文件存储**: 支持自动按大小滚动日志（Rotate）。
    - **MySQL 存储**: 自动创建表结构，支持结构化查询。
- **AI 友好**: 记录原始 Hex 数据、解码后的内容及协议类型，便于后续机器学习分析。
- **超时管理**: 支持全局会话超时，防止恶意连接占用资源。
- **容器化部署**: 提供 Docker 支持。

## 3. 配置说明 (环境变量)

系统通过环境变量进行配置：

| 变量名 | 描述 | 默认值 |
| :--- | :--- | :--- |
| `LISTEN_PORTS` | 监听的端口列表（逗号分隔） | `80,443,8080` |
| `STORAGE_TYPE` | 存储类型 (`file` 或 `mysql`) | `file` |
| `LOG_FILE` | 文件存储时的日志路径 | `/var/log/trap/honey.log` |
| `LOG_MAX_SIZE_MB` | 单个日志文件的最大大小（MB） | `10` |
| `MYSQL_HOST` | MySQL 服务器地址 | `localhost` |
| `MYSQL_USER` | MySQL 用户名 | `root` |
| `MYSQL_PASSWORD` | MySQL 密码 | (空) |
| `MYSQL_DATABASE` | MySQL 数据库名 | `trap` |
| `SESSION_TIMEOUT` | 单个连接的最长存活时间（秒） | `30` |

## 4. 模块详细设计

### 4.1 核心逻辑 (`main.py`)
使用 `asyncio` 实现异步并发处理。`Honeypot` 类负责初始化存储引擎和处理器链，并在 `handle_connection` 中循环读取数据，直到客户端关闭或达到超时限制。

### 4.2 协议处理 (`src/trap/handlers/`)
- **ProtocolHandler (基类)**: 定义了 `identify` (识别) 和 `handle` (处理) 接口。
- **HTTPHandler**: 识别常见的 HTTP 请求（GET, POST 等），并返回一个模拟的 nginx 欢迎页面。
- **DefaultHandler**: 后备处理器，对任何流量都尝试 UTF-8 解码，并返回简单的 "OK"。

### 4.3 数据持久化 (`src/trap/storage/`)
- **FileStorage**: 将记录保存为 JSON 行格式（JSONL），支持文件大小监控和重命名备份。
- **MySQLStorage**: 自动检测并创建 `records` 表。表结构包含原始数据的 Hex 编码和解码文本，并预留了 `metadata` JSON 字段以备扩展。

## 5. 开发与部署

### 5.1 环境要求
- Python 3.12+
- uv (项目管理工具)

### 5.2 本地运行
```bash
# 安装依赖
uv sync
# 运行服务
uv run -m src.trap.main
```

### 5.3 Docker 部署
项目根目录提供了 `Dockerfile` 和 `docker-compose.yml`。
```bash
docker-compose up -d
```

## 6. 数据格式示例 (JSON)

```json
{
  "timestamp": "2026-04-10T10:00:00.123456",
  "sender_ip": "192.168.1.100",
  "content_hex": "474554202f20485454502f312e31...",
  "decoded_content": "GET / HTTP/1.1\r\nHost: ...",
  "protocol": "http"
}
```
