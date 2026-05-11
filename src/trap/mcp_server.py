import os
import json
import asyncio
import uvicorn
import sys
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Request
from mcp.server import Server
from mcp.server.sse import SseServerTransport
import mcp.types as types

# --- 核心逻辑：日志搜索 ---

LOG_FILE = os.getenv("LOG_FILE", "/var/log/trap/honey.log")

def log_error(msg):
    print(msg, file=sys.stderr)

def fetch_logs_from_file(start_time: datetime, end_time: Optional[datetime] = None, limit: int = 1000) -> List[Dict[str, Any]]:
    """
    从日志文件中搜索指定时间范围内的记录。
    """
    results = []
    if not os.path.exists(LOG_FILE):
        return results

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                if len(results) >= limit:
                    break
                    
                try:
                    entry = json.loads(line)
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    
                    # 统一转换为 naive datetime 进行比较，防止 aware 和 naive 混用导致的 TypeError
                    if entry_time.tzinfo is not None:
                        entry_time = entry_time.replace(tzinfo=None)
                    
                    # 确保 start_time 和 end_time 也是 naive
                    search_start = start_time.replace(tzinfo=None) if start_time.tzinfo is not None else start_time
                    search_end = end_time.replace(tzinfo=None) if end_time and end_time.tzinfo is not None else end_time
                    
                    if entry_time >= search_start:
                        if search_end is None or entry_time <= search_end:
                            results.append(entry)
                        elif entry_time > search_end:
                            # 假设日志是按时间顺序排列的，如果超过了 end_time，可以提前退出
                            break
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except Exception as e:
        log_error(f"Error reading log file: {e}")
        
    return results

# --- MCP Server 定义 ---

mcp_app = Server("log-fetcher")

@mcp_app.list_tools()
async def list_tools() -> List[types.Tool]:
    return [
        types.Tool(
            name="fetch_logs",
            description="Fetch honeypot logs for a specific time range",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_time": {"type": "string", "description": "ISO 8601 start time (e.g. 2026-04-28T12:00:00)"},
                    "end_time": {"type": "string", "description": "ISO 8601 end time (optional)"},
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
            
            start_time = datetime.fromisoformat(start_str)
            end_time = datetime.fromisoformat(end_str) if end_str else None
            
            logs = fetch_logs_from_file(start_time, end_time)
            return [types.TextContent(type="text", text=json.dumps(logs, indent=2))]
        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]
    
    raise ValueError(f"Tool not found: {name}")

# --- HTTP Mode (REST API) ---

http_app = FastAPI(title="Log Fetcher REST API")

@http_app.get("/logs")
async def get_logs(
    start_time: str = Query(..., description="ISO 8601 start time"),
    end_time: Optional[str] = Query(None, description="ISO 8601 end time")
):
    try:
        start_dt = datetime.fromisoformat(start_time)
        end_dt = datetime.fromisoformat(end_time) if end_time else None
        return fetch_logs_from_file(start_dt, end_dt)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid date format: {e}")

# --- SSE Mode (MCP SSE) ---

sse_app = FastAPI(title="Log Fetcher MCP SSE")
sse_transport = SseServerTransport("/messages")

@sse_app.get("/sse")
async def sse_endpoint(request: Request):
    async with sse_transport.connect_sse(request.scope, request.receive, request._send) as sse:
        await mcp_app.run(
            sse.read_stream,
            sse.write_stream,
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
