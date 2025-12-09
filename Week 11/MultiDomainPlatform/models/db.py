import sqlite3
from pathlib import Path

DB_PATH = Path("database") / "intelligence_platform.db"

def connect_database(db_path=DB_PATH):
    """
    Connect to SQLite database.
    Creates the database if it doesn't exist.
    """
    return sqlite3.connect(str(db_path))