import os
import json
import asyncio
import uvicorn
import sys
import glob
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Request
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

# --- 核心逻辑：日志搜索 ---

LOG_FILE = os.getenv("LOG_FILE", "/var/log/trap/honey.log")

def log_error(msg):
    print(msg, file=sys.stderr)

def fetch_logs_from_file(
    start_time: datetime, 
    end_time: Optional[datetime] = None, 
    limit: int = 100, 
    offset: int = 0
) -> Dict[str, Any]:
    """
    从日志文件及其历史轮转文件中搜索指定时间范围内的记录，支持分页。
    """
    results = []
    
    # 查找所有匹配的文件（当前的和轮转后的）
    log_pattern = LOG_FILE + "*"
    all_files = glob.glob(log_pattern)
    all_files = [f for f in all_files if os.path.isfile(f)]
    
    # 按修改时间从新到旧排序
    all_files.sort(key=os.path.getmtime, reverse=True)

    def to_utc_aware(dt: Optional[datetime]):
        if dt is None: return None
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    utc_start = to_utc_aware(start_time)
    utc_end = to_utc_aware(end_time)

    skipped = 0
    found_count = 0

    for file_path in all_files:
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                for line in reversed(lines):
                    try:
                        entry = json.loads(line)
                        # 兼容处理带 Z 的 ISO 格式 (Python < 3.11)
                        ts_str = entry['timestamp'].replace('Z', '+00:00')
                        entry_time = datetime.fromisoformat(ts_str)
                        
                        if entry_time.tzinfo is None:
                            entry_time = entry_time.replace(tzinfo=timezone.utc)
                        
                        if entry_time >= utc_start and (utc_end is None or entry_time <= utc_end):
                            found_count += 1
                            if skipped < offset:
                                skipped += 1
                                continue
                            
                            if len(results) < limit:
                                results.append(entry)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except Exception as e:
            log_error(f"Error reading log file {file_path}: {e}")
        
    return {
        "logs": results,
        "total": found_count,
        "limit": limit,
        "offset": offset,
        "has_more": found_count > (offset + len(results))
    }

# --- MCP Server 定义 ---

mcp_app = Server("log-fetcher")

@mcp_app.list_tools()
async def list_tools() -> List[types.Tool]:
    return [
        types.Tool(
            name="fetch_logs",
            description="Fetch honeypot logs for a specific time range with pagination",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "description": "ISO 8601 start time (e.g. 2026-04-28T12:00:00)"},
                    "end_time": {"type": "string", "description": "ISO 8601 end time (optional)"},
                    "limit": {"type": "integer", "description": "Maximum number of logs to return (default: 100)", "default": 100},
                    "offset": {"type": "integer", "description": "Number of logs to skip (default: 0)", "default": 0},
                },
                "required": ["start_time"],
            },
        )
    ]

@mcp_app.call_tool()
async def call_tool(name: str, arguments: Any) -> List[types.TextContent]:
    if name == "fetch_logs":
        try:
            start_str = arguments.get("start_time")
            end_str = arguments.get("end_time")
            limit = int(arguments.get("limit", 100))
            offset = int(arguments.get("offset", 0))
            
            # 健壮的时间解析
            def parse_ts(ts_str):
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))

            start_time = parse_ts(start_str)
            end_time = parse_ts(end_str) if end_str else None
            
            result_data = fetch_logs_from_file(start_time, end_time, limit, offset)
            return [types.TextContent(type="text", text=json.dumps(result_data, indent=2))]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]
    
    raise ValueError(f"Tool not found: {name}")

# --- HTTP Mode (REST API) ---

http_app = FastAPI(title="Log Fetcher REST API")

@http_app.get("/logs")
async def get_logs(
    start_time: str = Query(..., description="ISO 8601 start time"),
    end_time: Optional[str] = Query(None, description="ISO 8601 end time"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
):
    try:
        def parse_ts(ts_str):
            return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            
        start_dt = parse_ts(start_time)
        end_dt = parse_ts(end_time) if end_time else None
        return fetch_logs_from_file(start_dt, end_dt, limit, offset)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid parameters: {e}")

# --- SSE Mode (MCP SSE) ---

sse_app = FastAPI(title="Log Fetcher MCP SSE")
sse_transport = SseServerTransport("/messages")

@sse_app.get("/sse")
async def sse_endpoint(request: Request):
    async with sse_transport.connect_sse(request.scope, request.receive, request._send) as (read_stream, write_stream):
        await mcp_app.run(
            read_stream,
            write_stream,
            mcp_app.create_initialization_options()
        )

@sse_app.post("/messages")
async def messages_endpoint(request: Request):
    await sse_transport.handle_post_message(request.scope, request.receive, request._send)

# --- 启动逻辑 ---

async def start_mcp_servers():
    http_enabled = os.getenv("MCP_HTTP_ENABLED", "true").lower() == "true"
    sse_enabled = os.getenv("MCP_SSE_ENABLED", "false").lower() == "true"
    
    try:
        http_port = int(os.getenv("MCP_HTTP_PORT", "8088"))
    except ValueError:
        log_error(f"Warning: Invalid MCP_HTTP_PORT. Defaulting to 8088.")
        http_port = 8088
        
    try:
        sse_port = int(os.getenv("MCP_SSE_PORT", "8089"))
    except ValueError:
        log_error(f"Warning: Invalid MCP_SSE_PORT. Defaulting to 8089.")
        sse_port = 8089
    
    tasks = []
    
    if http_enabled:
        log_error(f"Starting MCP HTTP (REST) server on 0.0.0.0:{http_port}...")
        http_config = uvicorn.Config(http_app, host="0.0.0.0", port=http_port, log_level="info")
        http_server = uvicorn.Server(http_config)
        tasks.append(asyncio.create_task(http_server.serve()))
        
    if sse_enabled:
        log_error(f"Starting MCP SSE server on 0.0.0.0:{sse_port}...")
        sse_config = uvicorn.Config(sse_app, host="0.0.0.0", port=sse_port, log_level="info")
        sse_server = uvicorn.Server(sse_config)
        tasks.append(asyncio.create_task(sse_server.serve()))
        
    return tasks

if __name__ == "__main__":
    # 保留独立运行能力用于调试
    async def run_standalone():
        tasks = await start_mcp_servers()
        if not tasks:
            log_error("No MCP modes enabled. Exiting.")
            return
        await asyncio.gather(*tasks)

    try:
        asyncio.run(run_standalone())
    except KeyboardInterrupt:
        pass
