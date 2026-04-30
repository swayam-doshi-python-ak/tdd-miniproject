import hashlib
import secrets

# ─────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────
MIN_PASSWORD_LENGTH = 6
TOKEN_BYTE_LENGTH = 32


class AuthSystem:
    """
    In-memory authentication system.

    Responsibilities:
        - Register users with hashed passwords
        - Login and issue secure session tokens
        - Authenticate requests via token
        - Logout and invalidate tokens

    Not responsible for:
        - Persistence (no DB here)
        - Password reset
        - Email verification
    """

    def __init__(self) -> None:
        self._users: dict[str, dict] = {}
        self._sessions: dict[str, str] = {}

    # ─────────────────────────────────────
    # PRIVATE HELPERS
    # ─────────────────────────────────────

    def _hash_password(self, password: str) -> str:
        """One-way SHA-256 hash of a plain text password."""
        return hashlib.sha256(password.encode()).hexdigest()

    def _generate_token(self) -> str:
        """Cryptographically secure random session token."""
        return secrets.token_hex(TOKEN_BYTE_LENGTH)

    def _get_user(self, username: str) -> dict | None:
        """Fetch a user record. Returns None if not found."""
        return self._users.get(username)

    def _is_valid_token(self, token: str) -> bool:
        """Check if a token exists in active sessions."""
        return token in self._sessions

    # ─────────────────────────────────────
    # VALIDATION
    # ─────────────────────────────────────

    def _validate_registration(self, username: str, password: str) -> str | None:
        """
        Validate registration input.
        Returns error message string or None if valid.
        """
        if not username:
            return "Username cannot be empty"
        if len(password) < MIN_PASSWORD_LENGTH:
            return "Password must be at least 6 characters"
        if username in self._users:
            return "User already exists"
        return None

    # ─────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────

    def register(self, username: str, password: str) -> dict:
        """
        Register a new user.

        Args:
            username: Must be non-empty string
            password: Must be at least 6 characters

        Returns:
            {"success": True, "message": ...}
            {"success": False, "message": ...}
        """
        error = self._validate_registration(username, password)
        if error:
            return {"success": False, "message": error}

        self._users[username] = {
            "password": self._hash_password(password)
        }
        return {"success": True, "message": "User registered successfully"}

    def login(self, username: str, password: str) -> dict:
        """
        Authenticate a user and issue a session token.

        Security note: Returns same error for wrong username
        AND wrong password to prevent user enumeration attacks.

        Returns:
            {"success": True, "token": ...}
            {"success": False, "message": ...}
        """
        user = self._get_user(username)
        if not user or user["password"] != self._hash_password(password):
            return {"success": False, "message": "Invalid credentials"}

        token = self._generate_token()
        self._sessions[token] = username
        return {"success": True, "token": token}

    def authenticate(self, token: str) -> dict:
        """
        Validate a session token.

        Returns:
            {"success": True, "username": ...}
            {"success": False, "message": ...}
        """
        if not self._is_valid_token(token):
            return {"success": False, "message": "Invalid or expired token"}
        return {"success": True, "username": self._sessions[token]}

    def logout(self, token: str) -> dict:
        """
        Invalidate a session token.

        Returns:
            {"success": True, "message": ...}
            {"success": False, "message": ...}
        """
        if not self._is_valid_token(token):
            return {"success": False, "message": "Invalid or expired token"}
        del self._sessions[token]
        return {"success": True, "message": "Logged out successfully"}
