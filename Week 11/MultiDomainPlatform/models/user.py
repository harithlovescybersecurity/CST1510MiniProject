from .db import connect_database

class User:
    """Manages user operations"""
    def __init__(self):
        pass

    def get_user_by_username(self, username):
        """retrieves user by username"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        return user

    def insert_user(self, username, password_hash, role="user"):
        """inserts a new user"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        conn.commit()
        cursor.close()
        conn.close()

    def get_all_users(self):
        """get all users"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        cursor.close()
        conn.close()
        return users

    def update_user_role(self, username, role):
        """updates user role"""
        conn = connect_database()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET role = ? WHERE username = ?",
            (role, username)
        )
        conn.commit()
        conn.close()
        cursor.close()




