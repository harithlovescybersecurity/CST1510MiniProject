import sqlite3
from pathlib import Path

DATA_DIR = Path("DATA")
DB_PATH = Path("DATA") / "intelligence_platform.db"

def connect_database(db_path=DB_PATH):
    """
    Connect to SQLite database.
    Creates the database if it doesn't exist.

    Args:
        db_path:  Path to the database file

    Returns:
        sqlite3.Connection: Database connection object
    """
    return sqlite3.connect(str(db_path))