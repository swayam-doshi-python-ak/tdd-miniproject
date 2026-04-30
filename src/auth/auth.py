import hashlib
import secrets


class AuthSystem:

    def __init__(self):
        # { username: { "password": hashed_password } }
        self._users = {}

        # { token: username }
        self._sessions = {}

    # ─────────────────────────────────────
    # PRIVATE HELPERS
    # ─────────────────────────────────────

    def _hash_password(self, password: str) -> str:
        """
        SHA-256 hash.
        Same password always produces same hash → good for comparison.
        Never reversible → passwords are safe even if data leaks.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def _generate_token(self) -> str:
        """
        Cryptographically secure random token.
        secrets module is safer than random module for auth tokens.
        64 hex chars = 32 bytes = virtually impossible to guess.
        """
        return secrets.token_hex(32)

    def _get_user(self, username: str) -> dict | None:
        """Internal method to fetch a user record by username."""
        return self._users.get(username)

    # ─────────────────────────────────────
    # VALIDATION
    # ─────────────────────────────────────

    def _validate_registration(self, username: str, password: str) -> str | None:
        """
        Returns an error message string if invalid.
        Returns None if everything is fine.
        """
        if not username:
            return "Username cannot be empty"
        if len(password) < 6:
            return "Password must be at least 6 characters"
        if username in self._users:
            return "User already exists"
        return None

    # ─────────────────────────────────────
    # REGISTRATION
    # ─────────────────────────────────────

    def register(self, username: str, password: str) -> dict:
        error = self._validate_registration(username, password)
        if error:
            return {"success": False, "message": error}

        self._users[username] = {
            "password": self._hash_password(password)
        }
        return {"success": True, "message": "User registered successfully"}

    # ─────────────────────────────────────
    # LOGIN
    # ─────────────────────────────────────

    def login(self, username: str, password: str) -> dict:
        user = self._get_user(username)

        # NOTE: We give the SAME error for wrong username OR wrong password.
        # This is a security best practice — attacker can't tell which one failed.
        if not user or user["password"] != self._hash_password(password):
            return {"success": False, "message": "Invalid credentials"}

        token = self._generate_token()
        self._sessions[token] = username
        return {"success": True, "token": token}

    # ─────────────────────────────────────
    # SESSION / TOKEN
    # ─────────────────────────────────────

    def authenticate(self, token: str) -> dict:
        username = self._sessions.get(token)
        if not username:
            return {"success": False, "message": "Invalid or expired token"}
        return {"success": True, "username": username}

    # ─────────────────────────────────────
    # LOGOUT
    # ─────────────────────────────────────

    def logout(self, token: str) -> dict:
        if token not in self._sessions:
            return {"success": False, "message": "Invalid or expired token"}
        del self._sessions[token]
        return {"success": True, "message": "Logged out successfully"}
