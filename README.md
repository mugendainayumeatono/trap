# Trap - Extensible Honeypot

A honeypot system that records incoming packets, identifies protocols, and supports multiple storage backends.

## Features
- Records timestamp, sender IP, hex content, and decoded content.
- Framework-based stateful protocol handlers for easy extension.
- **TLS 1.2 Support**: Fully simulates a TLS 1.2 handshake. Dynamically negotiates cipher suites, elliptic curves, and signature algorithms to adapt to modern scanners. Includes a simulated `Finished` state to capture full client probes without heavy cryptographic overhead.
- Storage support:
  - TXT file with size-based rotation.
  - MySQL database with automatic table creation and lazy initialization.
- Dockerized deployment with non-root user for security.
- Configurable via environment variables.

## Configuration
Use environment variables in `docker-compose.yml`:
- `STORAGE_TYPE`: `file` or `mysql`.
- `LOG_FILE`: Path to the log file (for `file` storage).
- `LOG_MAX_SIZE_MB`: Max size of log file before rotation.
- `LISTEN_PORTS`: Comma-separated list of ports to listen on inside the container.
- `TRUSTED_PROXIES`: Comma-separated list of IP ranges to trust for `X-Forwarded-For` and `PROXY` protocol. Use `*` to trust all proxies.
- `TLS_CERT_PATH`: Path to the DER-encoded certificate (default: `/app/certs/cert.der`).
- `TLS_KEY_PATH`: Path to the PEM-encoded private key (default: `/app/certs/cert.key`).
- `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`: MySQL connection details.
- `MCP_HTTP_ENABLED`: Enable REST API for logs (default: `true`).
- `MCP_SSE_ENABLED`: Enable MCP SSE server (default: `false`).
- `MCP_HTTP_PORT`: Port for REST API (default: `8088`).
- `MCP_SSE_PORT`: Port for MCP SSE (default: `8089`).

## MCP (Model Context Protocol) Support
Trap includes a built-in MCP service that allows AI agents to fetch and analyze honeypot logs. It runs alongside the main honeypot process and supports two modes:

### 1. HTTP REST API
A simple JSON API to query logs by time range.
- **Endpoint**: `GET http://<host>:8088/logs`
- **Parameters**: 
    - `start_time` (Required): ISO 8601 format.
    - `end_time` (Optional): ISO 8601 format.
- **Example**: `curl "http://localhost:8088/logs?start_time=2026-05-10T00:00:00"`

### 2. MCP SSE Server
A standard MCP Server implementation using Server-Sent Events.
- **Endpoint**: `http://<host>:8089/sse`
- **Tool**: `fetch_logs(start_time, end_time)`
- **Note**: This mode is ideal for connecting Trap directly to MCP-compatible IDEs or agents.

*Note: Both modes return a maximum of 1000 entries per request to ensure performance.*

## Usage

### Docker (Recommended)
1. **Start the honeypot in the background:**
   ```bash
   docker compose up --build -d
   ```
2. **View live logs:**
   ```bash
   docker compose logs -f trap
   ```
   Or tail the data logs:
   ```bash
   tail -f logs/honey.log
   ```
3. **Stop the honeypot:**
   ```bash
   docker compose down
   ```

### Testing & Development
1. **Run the automated test suite:**
   Ensure you have `uv` installed, then run:
   ```bash
   uv run pytest test/
   ```
2. **Manually test the TLS endpoint:**
   Use OpenSSL to verify the honeypot's dynamic TLS handshake (assuming port 1080 is exposed):
   ```bash
   openssl s_client -connect 127.0.0.1:1080 -tls1_2 -legacy_renegotiation
   ```

## Adding New Protocols
Implement the `ProtocolHandler` interface in `src/trap/handlers/` and add the instance to the `handlers` list in `src/trap/main.py`. Use the `cleanup` hook to manage session state if needed.
