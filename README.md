# Trap - Extensible Honeypot

A honeypot system that records incoming packets, identifies protocols, and supports multiple storage backends.

## Features
- Records timestamp, sender IP, hex content, and decoded content.
- Framework-based protocol handlers for easy extension.
- Storage support:
  - TXT file with size-based rotation.
  - MySQL database with automatic table creation.
- Dockerized deployment with non-root user for security.
- Configurable via environment variables.

## Configuration
Use environment variables in `docker-compose.yml`:
- `STORAGE_TYPE`: `file` or `mysql`.
- `LOG_FILE`: Path to the log file (for `file` storage).
- `LOG_MAX_SIZE_MB`: Max size of log file before rotation.
- `LISTEN_PORTS`: Comma-separated list of ports to listen on inside the container.
- `MYSQL_HOST`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_DATABASE`: MySQL connection details.

## Usage
1. Build and start the containers:
   ```bash
   docker-compose up --build -d
   ```
2. View logs:
   ```bash
   tail -f logs/honey.log
   ```

## Adding New Protocols
Implement the `ProtocolHandler` interface in `src/trap/handlers/` and add the instance to the `handlers` list in `src/trap/main.py`.
