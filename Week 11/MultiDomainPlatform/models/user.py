class User:
    """Represents a user in the Multi Domain Platform."""
    def __init__(self, username: str, password_hash: str, role: str):
        self.__username = username
        self.__password_hash = password_hash
        self.__role = role

    def get_username(self) -> str:
        """return the username"""
        return self.__username

    def get_role(self) -> str:
        """return the users role"""
        return self.__role

    def get_password_hash(self) -> str:
        """return the password hash for authentication"""
        return self.__password_hash

    def verify_password(self, plain_password: str, hasher) -> bool:
        """check if a plain-text password matches this users hash.

        Args:
            plain_password: the plain text password to check
            hasher: an object with a 'check_password(plain, hashed)' method

        Returns:
            bool: True if the password matches, False otherwise"""
        return hasher.check_password(plain_password, self.__password_hash)

    def update_password(self, new_hash: str) -> None:
        """update the users password hash"""
        self.__password_hash = new_hash

    def update_role(self, new_role: str) -> None:
        """update the users role"""
        self.__role = new_role

    def __str__(self) -> str:
        """string for the user"""
        return f"User(username={self.__username}, role={self.__role})"


