import email.utils
from .base import ProtocolHandler

class DefaultHandler(ProtocolHandler):
    def identify(self, data: bytes) -> bool:
        return True

    def handle(self, data: bytes) -> tuple[str, str, bytes]:
        try:
            decoded = data.decode('utf-8', errors='replace')
        except:
            decoded = data.hex()
        return "unknown", decoded, b"OK\n"

class HTTPHandler(ProtocolHandler):
    def identify(self, data: bytes) -> bool:
        # Simple HTTP check
        return any(verb in data for verb in [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS "])

    def handle(self, data: bytes) -> tuple[str, str, bytes]:
        try:
            decoded = data.decode('utf-8', errors='replace')
        except:
            decoded = data.hex()
        
        # Make it look like a real HTTP server (e.g., Nginx)
        date_str = email.utils.formatdate(usegmt=True)
        body = b"<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n</body>\n</html>\n"
        
        headers = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: nginx/1.18.0 (Ubuntu)\r\n"
            f"Date: {date_str}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        response = headers + body
        return "http", decoded, response
