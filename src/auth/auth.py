import hashlib
import secrets

MIN_PASSWORD_LENGTH = 6
TOKEN_BYTE_LENGTH = 32


class DatabaseService:
    """Real DB would go here — we mock this in tests."""

    def get_user(self, username: str) -> dict | None:
        raise NotImplementedError

    def save_user(self, username: str, hashed_password: str) -> None:
        raise NotImplementedError

    def get_session(self, token: str) -> str | None:
        raise NotImplementedError

    def save_session(self, token: str, username: str) -> None:
        raise NotImplementedError

    def delete_session(self, token: str) -> None:
        raise NotImplementedError


class AuthSystem:

    def __init__(self, db: DatabaseService = None) -> None:
        self._db = db or DatabaseService()

    def _hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def _generate_token(self) -> str:
        return secrets.token_hex(TOKEN_BYTE_LENGTH)

    def register(self, username: str, password: str) -> dict:
        if not username:
            return {"success": False, "message": "Username cannot be empty"}
        if len(password) < MIN_PASSWORD_LENGTH:
            return {"success": False, "message": "Password must be at least 6 characters"}
        if self._db.get_user(username):
            return {"success": False, "message": "User already exists"}

        self._db.save_user(username, self._hash_password(password))
        return {"success": True, "message": "User registered successfully"}

    def login(self, username: str, password: str) -> dict:
        user = self._db.get_user(username)
        if not user or user["password"] != self._hash_password(password):
            return {"success": False, "message": "Invalid credentials"}

        token = self._generate_token()
        self._db.save_session(token, username)
        return {"success": True, "token": token}

    def authenticate(self, token: str) -> dict:
        username = self._db.get_session(token)
        if not username:
            return {"success": False, "message": "Invalid or expired token"}
        return {"success": True, "username": username}

    def logout(self, token: str) -> dict:
        if not self._db.get_session(token):
            return {"success": False, "message": "Invalid or expired token"}
        self._db.delete_session(token)
        return {"success": True, "message": "Logged out successfully"}
