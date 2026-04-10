import mysql.connector
from datetime import datetime
from .base import Storage

class MySQLStorage(Storage):
    def __init__(self, host, user, password, database="trap"):
        self.config = {
            'host': host,
            'user': user,
            'password': password,
            'database': database
        }

    def setup(self):
        # Create database and table if not exists
        conn = mysql.connector.connect(
            host=self.config['host'],
            user=self.config['user'],
            password=self.config['password']
        )
        cursor = conn.cursor()
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config['database']}")
        cursor.execute(f"USE {self.config['database']}")
        
        # Table structure designed for extensibility and AI analysis
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS records (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME,
                sender_ip VARCHAR(45),
                protocol VARCHAR(50),
                content_hex LONGTEXT,
                decoded_content LONGTEXT,
                metadata JSON,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        cursor.close()
        conn.close()

    def record(self, timestamp: datetime, sender_ip: str, content: bytes, decoded_content: str, protocol: str):
        conn = mysql.connector.connect(**self.config)
        cursor = conn.cursor()
        query = """
            INSERT INTO records (timestamp, sender_ip, protocol, content_hex, decoded_content)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (timestamp, sender_ip, protocol, content.hex(), decoded_content))
        conn.commit()
        cursor.close()
        conn.close()
