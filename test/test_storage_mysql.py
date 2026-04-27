import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
from trap.storage.mysql import MySQLStorage

@patch("mysql.connector.connect")
@patch("mysql.connector.pooling.MySQLConnectionPool")
def test_mysql_storage_setup(mock_pool, mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    mock_pool_instance = MagicMock()
    mock_pool_conn = MagicMock()
    mock_pool_cursor = MagicMock()
    mock_pool.return_value = mock_pool_instance
    mock_pool_instance.get_connection.return_value = mock_pool_conn
    mock_pool_conn.cursor.return_value = mock_pool_cursor
    
    storage = MySQLStorage("localhost", "user", "pass", "db")
    storage.setup()
    
    assert mock_connect.called
    assert mock_cursor.execute.called
    assert mock_pool.called
    assert mock_pool_cursor.execute.called
    
    # Check if it creates database and table
    calls_connect = [call[0][0] for call in mock_cursor.execute.call_args_list]
    assert any("CREATE DATABASE IF NOT EXISTS db" in c for c in calls_connect)
    
    calls_pool = [call[0][0] for call in mock_pool_cursor.execute.call_args_list]
    assert any("CREATE TABLE IF NOT EXISTS records" in c for c in calls_pool)

@patch("mysql.connector.connect")
@patch("mysql.connector.pooling.MySQLConnectionPool")
def test_mysql_storage_record(mock_pool, mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    mock_pool_instance = MagicMock()
    mock_pool_conn = MagicMock()
    mock_pool_cursor = MagicMock()
    mock_pool.return_value = mock_pool_instance
    mock_pool_instance.get_connection.return_value = mock_pool_conn
    mock_pool_conn.cursor.return_value = mock_pool_cursor
    
    storage = MySQLStorage("localhost", "user", "pass", "db")
    timestamp = datetime(2023, 1, 1, 12, 0, 0)
    storage.record(timestamp, "1.2.3.4", b"content", "decoded", "proto")
    
    assert mock_pool_instance.get_connection.called
    assert mock_pool_cursor.execute.called
    query = mock_pool_cursor.execute.call_args[0][0]
    args = mock_pool_cursor.execute.call_args[0][1]
    assert "INSERT INTO records" in query
    assert args == (timestamp, "1.2.3.4", "proto", b"content".hex(), "decoded")
    assert mock_pool_conn.commit.called
