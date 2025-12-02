def hash_password(plain_text_password):
    # Converting password to bytes
    password_bytes = plain_text_password.encode("utf-8")
    # using salt for security
    salt = bcrypt.gensalt()
    # using salt to hash the password
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode("utf-8")

def verify_password(plain_text_password, hashed_password):
    #converting both the inputs to bytes
    password_bytes = plain_text_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)

#used to store user information
USER_DATA_FILE = '../../DATA/users.txt'

def user_exists(username):
    # if the user data file doesnt exist then no users are registered
    if not os.path.exists(USER_DATA_FILE):
        return False
    # opens the file to check for username
    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username = line.strip().split(",")[0]
            if stored_username == username:
                return True
    return False

#checks if username exists
def register_user(username, password):
    if user_exists(username):
        return False
    # hashing the password
    hashed_password = hash_password(password)
    # adds the new user to the file
    with open(USER_DATA_FILE, "a") as file:
        file.write(f"{username},{hashed_password}\n")
    return True

def login_user(username, password):
    # if no user data file exists then no users are registered
    if not os.path.exists(USER_DATA_FILE):
        return False
    # searching for username in file
    with open(USER_DATA_FILE, 'r') as file:
        for line in file:
            parts = line.strip().split(',')
            if parts[0] == username:
                stored_hash = parts[1]
                # verifies the provided password with stored hash
                return verify_password(password, stored_hash)

    return False

def validate_username(username):
    # username has to be atleast 3 characters long
    if len(username) < 3:
        return False,
    return True, ""

def validate_password(password):
    # password must be atleast 6 characters long
    if len(password) < 6:
        return False,
    return True, ""

def display_menu():
    """Displays the main menu options."""
    print("\n" + "="*50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)

def main():
    """Main Program loop."""
    print("\nWelcome to the Week 7 Authentication System!")

    while True:
        # displays menu options to get user input
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- User Registration ---")
            username = input("Enter a username: ").strip()

            # username must meet requirements
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                # keeps looping if validation fails
                continue

            password = input("Enter a password: ").strip()

            # Validate password meets security requirements
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            #Register the user
            if register_user(username, password):
                print(f"Success: User '{username}' is registered successfully!")
            else:
                print(f"Error: Username '{username}' already exists")

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
                print("(In a real application, you would now access secured data")
                # Optional: Ask if they want to log out or exit
                input("\nPress Enter to return to main menu...")
            else:
                print("\nError: Invalid username or password.")

        elif choice == "3":
            # Exit
            print("\nThank you for using the authentication system")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    # program entry point
    main()





