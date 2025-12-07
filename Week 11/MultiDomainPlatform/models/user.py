class User:
    """Represents a user in the Multi Domain Platform."""
    def __init__(self, username: str, password_hash: str, role: str):
        self.username = username
        self.password_hash = password_hash
        self.role = role

    def get_username(self) -> str:
        return self.username

    def 