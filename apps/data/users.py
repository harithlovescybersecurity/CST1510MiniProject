from apps.data.db import connect_database

def get_user_by_username(username):
    """Retrieve user by username"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()
    return user

def insert_user(username, password_hash, role="user"):
    """Insert new user"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role)
    )
    conn.commit()
    conn.close()

def get_all_users():
    """Get all users"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

def update_user_role(username, role):
    """Update user role"""
    conn = connect_database()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET role = ? WHERE username = ?",
        (role, username)
    )
    conn.commit()
    conn.close()
