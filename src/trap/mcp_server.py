import os
import json
import asyncio
import uvicorn
import threading
import sys
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# --- 核心逻辑：日志搜索 ---

LOG_FILE = os.getenv("LOG_FILE", "/var/log/trap/honey.log")

def log_error(msg):
    print(msg, file=sys.stderr)

def fetch_logs_from_file(start_time: datetime, end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """
    从日志文件中搜索指定时间范围内的记录。
    """
    results = []
    if not os.path.exists(LOG_FILE):
        return results

    try:
        with open(LOG_FILE, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    entry_time = datetime.fromisoformat(entry['timestamp'])
                    
                    if entry_time >= start_time:
                        if end_time is None or entry_time <= end_time:
                            results.append(entry)
                        elif entry_time > end_time:
                            pass
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue
    except Exception as e:
        log_error(f"Error reading log file: {e}")
        
    return results

# --- MCP Server (stdio) ---

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

async def run_mcp_stdio():
    log_error("Running MCP stdio server...")
    try:
        async with stdio_server() as (read_stream, write_stream):
            await mcp_app.run(
                read_stream,
                write_stream,
                mcp_app.create_initialization_options()
            )
    except Exception as e:
        log_error(f"MCP stdio server error: {e}")

# --- HTTP Server (FastAPI) ---

http_app = FastAPI(title="Log Fetcher Local API")

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

# --- 主程序入口 ---

async def main():
    if os.getenv("MCP_HTTP_ENABLED", "true").lower() == "true":
        log_error("Starting HTTP server on 127.0.0.1:8088 in background...")
        config = uvicorn.Config(http_app, host="127.0.0.1", port=8088, log_level="info")
        server = uvicorn.Server(config)
        
        # 启动 HTTP 服务器任务
        http_task = asyncio.create_task(server.serve())
        
        # 尝试运行 MCP stdio
        try:
            await run_mcp_stdio()
        except Exception as e:
            log_error(f"Stdio server error: {e}")
        
        # 无论 stdio 发生了什么，只要开启了 HTTP，就继续运行
        log_error("Stdio finished. Keeping process alive for HTTP...")
        await http_task
    else:
        log_error("HTTP server disabled. Running stdio only.")
        await run_mcp_stdio()

if __name__ == "__main__":
    log_error("MCP Server starting...")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    log_error("MCP Server shutting down.")
