import pytest
from src.auth.auth import AuthSystem


# REGISTRATION TESTS

class TestRegistration:

    def test_register_new_user_successfully(self, auth):
        result = auth.register("alice", "password123")
        assert result["success"] is True
        assert result["message"] == "User registered successfully"

    def test_register_duplicate_user_fails(self, auth):
        auth.register("alice", "password123")
        result = auth.register("alice", "newpassword")
        assert result["success"] is False
        assert result["message"] == "User already exists"

    def test_password_not_stored_as_plain_text(self, auth):
        auth.register("alice", "password123")
        stored = auth._get_user("alice")
        assert stored["password"] != "password123"

    # PARAMETRIZE — test many inputs at once

    @pytest.mark.parametrize("username, password, expected_message", [
        ("",      "password123", "Username cannot be empty"),
        ("alice", "123",         "Password must be at least 6 characters"),
        ("alice", "12345",       "Password must be at least 6 characters"),
    ])
    def test_register_invalid_inputs(self, auth, username, password, expected_message):
        result = auth.register(username, password)
        assert result["success"] is False
        assert result["message"] == expected_message


# LOGIN TESTS // commit frequently 

class TestLogin:

    def test_login_correct_credentials(self, registered_auth):
        result = registered_auth.login("alice", "password123")
        assert result["success"] is True
        assert "token" in result

    def test_login_returns_unique_tokens(self, registered_auth):
        token1 = registered_auth.login("alice", "password123")["token"]
        token2 = registered_auth.login("alice", "password123")["token"]
        assert token1 != token2

    @pytest.mark.parametrize("username, password", [
        ("alice", "wrongpassword"),   
        ("ghost", "password123"),     
        ("ALICE", "password123"),     
    ])
    def test_login_invalid_credentials(self, registered_auth, username, password):
        result = registered_auth.login(username, password)
        assert result["success"] is False
        assert result["message"] == "Invalid credentials"


# SESSION TESTS AUTHENTICATION TESTS


class TestSession:

    def test_valid_token_authenticates(self, logged_in_auth):
        auth, token = logged_in_auth
        result = auth.authenticate(token)
        assert result["success"] is True
        assert result["username"] == "alice"

    def test_invalid_token_rejected(self, auth):
        result = auth.authenticate("totally-fake-token")
        assert result["success"] is False
        assert result["message"] == "Invalid or expired token"

    def test_logout_invalidates_token(self, logged_in_auth):
        auth, token = logged_in_auth
        auth.logout(token)
        result = auth.authenticate(token)
        assert result["success"] is False

    def test_logout_invalid_token_fails(self, auth):
        result = auth.logout("invalid-token")
        assert result["success"] is False

    def test_multiple_sessions_independent(self, registered_auth):
        """
        Alice logs in twice → two independent tokens.
        Logging out one should NOT affect the other.
        """
        token1 = registered_auth.login("alice", "password123")["token"]
        token2 = registered_auth.login("alice", "password123")["token"]

        registered_auth.logout(token1)

        assert registered_auth.authenticate(token1)["success"] is False  # dead
        assert registered_auth.authenticate(token2)["success"] is True   # alive












# uv run pytest tests/test_auth_pytest.py -v