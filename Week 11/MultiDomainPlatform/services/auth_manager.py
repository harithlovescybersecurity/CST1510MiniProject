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
        hashed_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hashed_bytes)

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

    def check_username_availability(self, username):
        """checks if a username exists"""
        exists = self.user_exists(username)
        if exists:
            return False, f"Username '{username}' is already registered"
        return True, f"Username '{username}' is available"

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

    def validate_username(self, username):
        """validates a username"""
        if len(username) < 3:
            return False,
        return True, ""

    def validate_password(self, password):
        """validates a password"""
        if len(password) < 8:
            return False,
        return True, ""

def display_menu():
    """displays menu"""
    print("\n" + "="*50)
    print("MULTI DOMAIN PLATFORM")
    print("Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")

def main():
    """main function"""
    print("\nWelcome to the Multi-Domain Intelligence Platform Authentication System!")

    auth = AuthManager()

    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == "1":
            print("\n--- User Registration ---")
            username = input("Enter a username: ").strip()
            is_available, availability_msg =  auth.check_username_availability(username)
            print(f" {availability_msg}")
            if not is_available:
                continue

            is_valid, error_msg = auth.validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()
            is_valid, error_msg = auth.validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            if auth.register_user(username, password):
                print(f"Success: User '{username}' registered successfully!")
            else:
                print(f"Error: Username '{username}' already exists!")

        elif choice == "2":
            print("\n--- USER LOGIN ---")
            username = input("Enter a username: ").strip()
            password = input("Enter a password: ").strip()

            #attempt login
            if auth.login_user(username, password):
                print("\nYou are now logged in!")
                input("Press enter to continue...")
            else:
                print("\nError: Invalid username or password!")

        elif choice == "3":
            #exit
            print("\nThank you for using Multi-Domain Platform!")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select an option (1-3).")

if __name__ == "__main__":
    main()