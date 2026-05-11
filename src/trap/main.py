import asyncio
import os
import signal
import ipaddress
import re
from datetime import datetime, timezone
from .storage.file import FileStorage
from .storage.mysql import MySQLStorage
from .handlers.default import DefaultHandler, HTTPHandler
from .handlers.tls import TLSHandler
from .mcp_server import start_mcp_servers

class Honeypot:
    def __init__(self):
        self.storage = self._setup_storage()
        self.handlers = [TLSHandler(), HTTPHandler(), DefaultHandler()]
        self._setup_trusted_proxies()

    def _setup_trusted_proxies(self):
        trusted_proxies_env = os.getenv("TRUSTED_PROXIES", "")
        self.trusted_proxies = []
        self.trust_all_proxies = (trusted_proxies_env == "*")
        if trusted_proxies_env and not self.trust_all_proxies:
            for p in trusted_proxies_env.split(","):
                try:
                    self.trusted_proxies.append(ipaddress.ip_network(p.strip()))
                except ValueError:
                    pass

    def _is_trusted_proxy(self, ip_str):
        if self.trust_all_proxies:
            return True
        if not self.trusted_proxies or not ip_str:
            return False
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in self.trusted_proxies)
        except ValueError:
            return False

    def _setup_storage(self):
        storage_type = os.getenv("STORAGE_TYPE", "file").lower()
        if storage_type == "mysql":
            storage = MySQLStorage(
                host=os.getenv("MYSQL_HOST", "localhost"),
                user=os.getenv("MYSQL_USER", "root"),
                password=os.getenv("MYSQL_PASSWORD", ""),
                database=os.getenv("MYSQL_DATABASE", "trap")
            )
        else:
            try:
                max_size_mb = float(os.getenv("LOG_MAX_SIZE_MB", "10"))
            except ValueError:
                print("Warning: Invalid LOG_MAX_SIZE_MB value. Defaulting to 10MB.")
                max_size_mb = 10.0
                
            try:
                max_days = float(os.getenv("LOG_MAX_DAYS", "0"))
            except ValueError:
                print("Warning: Invalid LOG_MAX_DAYS value. Defaulting to 0 (disabled).")
                max_days = 0.0
                
            storage = FileStorage(
                file_path=os.getenv("LOG_FILE", "/var/log/trap/honey.log"),
                max_size_mb=max_size_mb,
                max_days=max_days
            )
        storage.setup()
        return storage

    async def handle_connection(self, reader, writer):
        peer = writer.get_extra_info('peername')
        
        if isinstance(peer, str):
            normalized_ip = peer
        elif peer:
            try:
                # Normalize IP
                normalized_ip = str(ipaddress.ip_address(peer[0]))
            except ValueError:
                normalized_ip = str(peer[0])
        else:
            normalized_ip = "unknown"
            
        real_ip = normalized_ip
        session_id = f"{normalized_ip}:{peer[1]}" if peer and not isinstance(peer, str) else normalized_ip
        current_handler = None
        is_first_read = True
        
        # Set session timeout
        try:
            session_timeout = float(os.getenv("SESSION_TIMEOUT", "30"))
        except ValueError:
            session_timeout = 30.0
            
        start_time = asyncio.get_event_loop().time()
        end_time = start_time + session_timeout

        try:
            while True:
                current_time = asyncio.get_event_loop().time()
                remaining_time = end_time - current_time
                if remaining_time <= 0:
                    break

                try:
                    # Use wait_for to implement absolute session timeout for the read operation
                    data = await asyncio.wait_for(reader.read(4096), timeout=remaining_time)
                except (asyncio.TimeoutError, ConnectionError):
                    break

                if not data:
                    break

                if is_first_read and self._is_trusted_proxy(normalized_ip):
                    if data.startswith(b"PROXY "):
                        line_end = data.find(b"\r\n")
                        if line_end == -1:
                            line_end = data.find(b"\n")
                        
                        if line_end != -1:
                            parts = data[:line_end].split(b" ")
                            if len(parts) >= 3:
                                try:
                                    real_ip = str(ipaddress.ip_address(parts[2].decode('ascii')))
                                    data = data[line_end + (2 if data[line_end:line_end+2] == b"\r\n" else 1):]
                                    if not data:
                                        is_first_read = False
                                        continue
                                except (ValueError, UnicodeDecodeError):
                                    pass
                    
                    if b"HTTP/" in data:
                        try:
                            # Handle both \r\n\r\n and \n\n as header separators
                            headers_end = data.find(b"\r\n\r\n")
                            if headers_end == -1:
                                headers_end = data.find(b"\n\n")
                            
                            headers_part = data[:headers_end].decode('ascii', errors='ignore') if headers_end != -1 else data.decode('ascii', errors='ignore')
                            
                            # Match X-Forwarded-For or X-Real-IP at start of string or after newline
                            match = re.search(r'(?i)(?:^|[\r\n])(?:X-Forwarded-For|X-Real-IP):\s*([^\r\n]+)', headers_part)
                            if match:
                                ips = [ip.strip() for ip in match.group(1).split(',')]
                                if ips:
                                    real_ip = str(ipaddress.ip_address(ips[0]))
                        except (ValueError, IndexError):
                            pass
                is_first_read = False

                timestamp = datetime.now(timezone.utc)
                protocol_name = "unknown"
                decoded_content = ""
                response = b""

                if current_handler:
                    protocol_name, decoded_content, response = current_handler.handle(data, session_id)
                else:
                    for handler in self.handlers:
                        if handler.identify(data):
                            current_handler = handler
                            protocol_name, decoded_content, response = handler.handle(data, session_id)
                            break

                if response:
                    writer.write(response)
                    await writer.drain()

                try:
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(
                        None, 
                        self.storage.record, 
                        timestamp, real_ip, data, decoded_content, protocol_name
                    )
                except Exception as e:
                    print(f"Error recording connection from {real_ip}: {e}")
                
                # If we have reached the session timeout after writing, break
                if asyncio.get_event_loop().time() >= end_time:
                    break
        except Exception as e:
            print(f"Error handling connection from {real_ip}: {e}")
        finally:
            if current_handler and hasattr(current_handler, 'cleanup'):
                try:
                    current_handler.cleanup(session_id)
                except Exception as cleanup_err:
                    print(f"Error during handler cleanup for {real_ip}: {cleanup_err}")
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def listen(self, host, port):
        try:
            server = await asyncio.start_server(self.handle_connection, host, port)
        except OSError as e:
            print(f"Error: Failed to bind to {host}:{port} - {e}")
            return
            
        addr = server.sockets[0].getsockname()
        print(f"Listening on {addr}")
        async with server:
            await server.serve_forever()

async def main():
    ports = os.getenv("LISTEN_PORTS", "80,443,8080").split(",")
    honeypot = Honeypot()
    tasks = []
    for port in ports:
        try:
            p = int(port.strip())
            tasks.append(honeypot.listen('0.0.0.0', p))
        except ValueError:
            print(f"Warning: Invalid port '{port.strip()}'. Skipping.")
    
    if not tasks:
        print("Warning: No valid honey ports configured.")

    # Start MCP servers
    mcp_tasks = await start_mcp_servers()
    
    if not tasks and not mcp_tasks:
        print("Error: No services (Honeypot or MCP) are enabled. Exiting.")
        return

    await asyncio.gather(*tasks, *mcp_tasks)

if __name__ == "__main__":
    asyncio.run(main())
