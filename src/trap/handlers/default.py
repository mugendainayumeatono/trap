import email.utils
from .base import ProtocolHandler
from .php_rce import PHP2ShellEngine, PHPSandboxSimulator

class DefaultHandler(ProtocolHandler):
    def identify(self, data: bytes) -> bool:
        return True

    def handle(self, data: bytes, session_id: str = "") -> tuple[str, str, bytes]:
        try:
            decoded = data.decode('utf-8', errors='replace')
        except:
            decoded = data.hex()
        return "unknown", decoded, b"OK\n"

class HTTPHandler(ProtocolHandler):
    METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT ", b"TRACE ", b"PATCH ")

    def __init__(self):
        self.php_engine = PHP2ShellEngine()

    def identify(self, data: bytes) -> bool:
        # Simple HTTP check: request line must start with a valid HTTP method
        return data.lstrip(b"\r\n").startswith(self.METHODS)

    def handle(self, data: bytes, session_id: str = "") -> tuple[str, str, bytes]:
        # Delegate to PHP2ShellEngine if buffering or if request matches PHP / PHP2Shell patterns
        php_result = self.php_engine.process_chunk(data, session_id)
        if php_result is not None:
            return php_result

        try:
            decoded = data.decode('utf-8', errors='replace')
        except:
            decoded = data.hex()
        
        # Make it look like a real HTTP server with vulnerable PHP runtime exposed
        date_str = email.utils.formatdate(usegmt=True)
        body = b"<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n</body>\n</html>\n"
        
        headers = (
            f"HTTP/1.1 200 OK\r\n"
            f"Server: nginx/1.18.0 (Ubuntu)\r\n"
            f"X-Powered-By: PHP/{PHPSandboxSimulator.PHP_VERSION}\r\n"
            f"Date: {date_str}\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode('utf-8')
        
        response = headers + body
        return "http", decoded, response

    def cleanup(self, session_id: str = "") -> None:
        self.php_engine.cleanup_session(session_id)
