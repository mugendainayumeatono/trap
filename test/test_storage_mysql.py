import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime
from trap.storage.mysql import MySQLStorage

@patch("mysql.connector.connect")
def test_mysql_storage_setup(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor
    
    storage = MySQLStorage("localhost", "user", "pass", "db")
    storage.setup()
    
    assert mock_connect.called
    assert mock_cursor.execute.called
    # Check if it creates database and table
    calls = [call[0][0] for call in mock_cursor.execute.call_args_list]
    assert any("CREATE DATABASE IF NOT EXISTS db" in c for c in calls)
    assert any("CREATE TABLE IF NOT EXISTS records" in c for c in calls)

@patch("mysql.connector.connect")
def test_mysql_storage_record(mock_connect):
    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_connect.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor
    
    storage = MySQLStorage("localhost", "user", "pass", "db")
    timestamp = datetime(2023, 1, 1, 12, 0, 0)
    storage.record(timestamp, "1.2.3.4", b"content", "decoded", "proto")
    
    assert mock_connect.called
    assert mock_cursor.execute.called
    query = mock_cursor.execute.call_args[0][0]
    args = mock_cursor.execute.call_args[0][1]
    assert "INSERT INTO records" in query
    assert args == (timestamp, "1.2.3.4", "proto", b"content".hex(), "decoded")
    assert mock_conn.commit.called
