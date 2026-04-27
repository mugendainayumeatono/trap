import mysql.connector
from mysql.connector import pooling
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
        self.pool = None

    def setup(self):
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
        try:
            self.pool = mysql.connector.pooling.MySQLConnectionPool(
                pool_name="trap_pool",
                pool_size=5,
                pool_reset_session=True,
                **self.config
            )
        except mysql.connector.Error as err:
            print(f"Error creating connection pool: {err}")
            raise

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

    def record(self, timestamp: datetime, sender_ip: str, content: bytes, decoded_content: str, protocol: str):
        if not self.pool:
            print("Warning: Connection pool not initialized. Attempting to initialize.")
            try:
                self.setup()
            except Exception as e:
                print(f"Error during lazy MySQL setup: {e}")
                return
            
        conn = None
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
