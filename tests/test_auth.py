import unittest
from src.auth.auth import AuthSystem


class TestAuthRegistration(unittest.TestCase):
    """Tests for user registration"""

    def setUp(self):
        """
        Runs BEFORE every single test.
        Always gives us a fresh AuthSystem — tests never affect each other.
        """
        self.auth = AuthSystem()

    def tearDown(self):
        """
        Runs AFTER every single test.
        Clean up anything if needed (close DB, clear files etc.)
        Here our AuthSystem is in-memory so nothing to do — but good habit!
        """
        self.auth = None

    # ─────────────────────────────────────
    # REGISTRATION
    # ─────────────────────────────────────

    def test_register_new_user_successfully(self):
        result = self.auth.register("alice", "password123")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "User registered successfully")

    def test_register_duplicate_user_fails(self):
        self.auth.register("alice", "password123")
        result = self.auth.register("alice", "newpassword")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "User already exists")

    def test_password_is_not_stored_as_plain_text(self):
        self.auth.register("alice", "password123")
        stored = self.auth._get_user("alice")
        self.assertNotEqual(stored["password"], "password123")

    def test_register_with_empty_username_fails(self):
        result = self.auth.register("", "password123")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Username cannot be empty")

    def test_register_with_short_password_fails(self):
        result = self.auth.register("alice", "123")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Password must be at least 6 characters")


class TestAuthLogin(unittest.TestCase):
    """Tests for login logic"""

    def setUp(self):
        self.auth = AuthSystem()
        # Pre-register a user so login tests don't repeat registration
        self.auth.register("alice", "password123")

    def tearDown(self):
        self.auth = None

    # ─────────────────────────────────────
    # LOGIN
    # ─────────────────────────────────────

    def test_login_with_correct_credentials(self):
        result = self.auth.login("alice", "password123")
        self.assertTrue(result["success"])
        self.assertIn("token", result)

    def test_login_with_wrong_password_fails(self):
        result = self.auth.login("alice", "wrongpassword")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid credentials")

    def test_login_with_nonexistent_user_fails(self):
        result = self.auth.login("ghost", "password123")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid credentials")

    def test_token_is_unique_per_login(self):
        token1 = self.auth.login("alice", "password123")["token"]
        token2 = self.auth.login("alice", "password123")["token"]
        self.assertNotEqual(token1, token2)


class TestAuthSession(unittest.TestCase):
    """Tests for token-based session management"""

    def setUp(self):
        self.auth = AuthSystem()
        self.auth.register("alice", "password123")
        # Login once and store token for session tests
        login_result = self.auth.login("alice", "password123")
        self.token = login_result["token"]

    def tearDown(self):
        self.auth = None
        self.token = None

    # ─────────────────────────────────────
    # SESSION / TOKEN
    # ─────────────────────────────────────

    def test_valid_token_authenticates_user(self):
        result = self.auth.authenticate(self.token)
        self.assertTrue(result["success"])
        self.assertEqual(result["username"], "alice")

    def test_invalid_token_fails_authentication(self):
        result = self.auth.authenticate("fake-token-xyz")
        self.assertFalse(result["success"])
        self.assertEqual(result["message"], "Invalid or expired token")

    # ─────────────────────────────────────
    # LOGOUT
    # ─────────────────────────────────────

    def test_logout_invalidates_token(self):
        self.auth.logout(self.token)
        result = self.auth.authenticate(self.token)
        self.assertFalse(result["success"])

    def test_logout_with_invalid_token_fails(self):
        result = self.auth.logout("invalid-token")
        self.assertFalse(result["success"])


if __name__ == "__main__":
    unittest.main()
