import bcrypt
import os
from pathlib import Path

class AuthManager:
    """manages user authentication"""
    def __init__(self, data_file="DATA/users.txt"):
        self.USER_DATA_FILE =str(Path(__file__).parent.parent / data_file)
        self._ensure_data_directory()

    def _ensure_data_directory(self):
        """ensures data directory exists"""
        data_dir = os.path.dirname(self.USER_DATA_FILE)
        if not os.path.exists(data_dir):
            os.makedirs(data_dir, exist_ok=True)

    def _hash_password(self, plain_text_password):
        """hashes plain text password"""
        password_bytes = plain_text_password.encode("utf-8")
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password_bytes, salt)
        return hashed_password.decode("utf-8")

    def _verify_password(self, plain_text_password, hashed_password):
        """verifies plain text password against hashed password"""
        password_bytes = plain_text_password.encode("utf-8")
        hashed_password = hashed_password.decode("utf-8")
        return bcrypt.checkpw(password_bytes, hashed_password)

    def user_exists(self, username):
        """checks if a user exists"""
        if not os.path.exists(self.USER_DATA_FILE):
            return False
        with open(self.USER_DATA_FILE, "r") as file:
            for line in file:
                stored_username = line.strip().split(",")[0]
                if stored_username == username:
                    return True
        return False

    def register_user(self, username, password):
        """registers a new user"""
        if self.user_exists(username):
            return False

        hashed_password = self._hash_password(password)
        with open(self.USER_DATA_FILE, "a") as file:
            file.write(f"{username},{hashed_password}\n")
        return True

    def login_user(self, username, password):
        """logs in a user"""
        if not os.path.exists(self.USER_DATA_FILE):
            return False
        with open(self.USER_DATA_FILE, "r") as file:
            for line in file:
                parts= line.strip().split(",")
                if parts[0] == username:
                    stored_hash = parts[1]
                    return self._verify_password(password, stored_hash)
        return False

    









