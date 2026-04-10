import asyncio
import os
import signal
from datetime import datetime
from .storage.file import FileStorage
from .storage.mysql import MySQLStorage
from .handlers.default import DefaultHandler, HTTPHandler

class Honeypot:
    def __init__(self):
        self.storage = self._setup_storage()
        self.handlers = [HTTPHandler(), DefaultHandler()]

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
            storage = FileStorage(
                file_path=os.getenv("LOG_FILE", "/var/log/trap/honey.log"),
                max_size_mb=float(os.getenv("LOG_MAX_SIZE_MB", "10"))
            )
        storage.setup()
        return storage

    async def handle_connection(self, reader, writer):
        peer = writer.get_extra_info('peername')
        sender_ip = peer[0] if peer else "unknown"
        
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

                timestamp = datetime.now()
                protocol_name = "unknown"
                decoded_content = ""
                response = b""

                for handler in self.handlers:
                    if handler.identify(data):
                        protocol_name, decoded_content, response = handler.handle(data)
                        break

                self.storage.record(timestamp, sender_ip, data, decoded_content, protocol_name)
                
                if response:
                    writer.write(response)
                    await writer.drain()
                
                # If we have reached the session timeout after writing, break
                if asyncio.get_event_loop().time() >= end_time:
                    break
        except Exception as e:
            print(f"Error handling connection from {sender_ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def listen(self, host, port):
        server = await asyncio.start_server(self.handle_connection, host, port)
        addr = server.sockets[0].getsockname()
        print(f"Listening on {addr}")
        async with server:
            await server.serve_forever()

async def main():
    ports = os.getenv("LISTEN_PORTS", "80,443,8080").split(",")
    honeypot = Honeypot()
    tasks = []
    for port in ports:
        tasks.append(honeypot.listen('0.0.0.0', int(port.strip())))
    
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
