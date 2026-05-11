import mysql.connector
from mysql.connector import pooling
from datetime import datetime
import threading
from .base import Storage

class MySQLStorage(Storage):
    def __init__(self, host, user, password, database="trap"):
        self.config = {
            'host': host,
            'user': user,
            'password': password,
            'database': database
        }
        self.pool = None
        self._lock = threading.Lock()

    def setup(self):
        with self._lock:
            if self.pool: # Double-check locking pattern
                return
                
            try:
                # Create database first (without database selected)
                conn = mysql.connector.connect(
                    host=self.config['host'],
                    user=self.config['user'],
                    password=self.config['password']
                )
                cursor = conn.cursor()
                cursor.execute(f"CREATE DATABASE IF NOT EXISTS {self.config['database']}")
                conn.commit()
                cursor.close()
                conn.close()

                # Now create the connection pool targeting the specific database
                self.pool = mysql.connector.pooling.MySQLConnectionPool(
                    pool_name="trap_pool",
                    pool_size=5,
                    pool_reset_session=True,
                    **self.config
                )

                # Table structure designed for extensibility and AI analysis
                conn = self.pool.get_connection()
                cursor = conn.cursor()
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
            except Exception as err:
                print(f"Error during MySQL setup (will retry lazily later): {err}")
                self.pool = None

    def record(self, timestamp: datetime, sender_ip: str, content: bytes, decoded_content: str, protocol: str):
        if not self.pool:
            self.setup()
            if not self.pool: # If setup still failed
                return
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor()
            query = """
                INSERT INTO records (timestamp, sender_ip, protocol, content_hex, decoded_content)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(query, (timestamp, sender_ip, protocol, content.hex(), decoded_content))
            conn.commit()
            cursor.close()
        except mysql.connector.Error as err:
            print(f"Error recording to MySQL: {err}")
        finally:
            if conn and conn.is_connected():
                conn.close() # Returns connection to pool
