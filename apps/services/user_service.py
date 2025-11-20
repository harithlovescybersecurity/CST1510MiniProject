import bcrypt
from pathlib import Path
from apps.data.db import connect_database
from apps.data.users import get_user_by_username, insert_user
from apps.data.schema import create_users_table

def register_user(username, password, role='user'):
    """Register new user with password hashing"""
    password_hash = bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')

    insert_user(username, password_hash, role)
    return True, f"User '{username}' registered successfully."

def login_user(username, password):
    """Authenticate user."""
    user = get_user_by_username(username)
    if not user:
        return False, "User not found."

    stored_hash = user[2]
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
        return True, f"Login successful!"
    return False, "Incorrect password."

def migrate_users_from_file(filepath='DATA/users.txt'):
    """Migrate users from text file to database"""
    path = Path(filepath)
    if not path.exists():
        print(f"File not found: {filepath}")
        return

    conn = connect_database()
    cursor = conn.cursor()
    migrated_count = 0

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split(',')
            if len(parts) >= 2:
                username = parts[0]
                password_hash = parts[1]

                try:
                    cursor.execute(
                        "INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                        (username, password_hash, 'user')
                    )
                    if cursor.rowcount > 0:
                        migrated_count += 1
                except Exception as e:
                    print(f"Error migrating user {username}: {e}")

    conn.commit()
    conn.close()
    print(f"Migrated {migrated_count} users from {path.name}")