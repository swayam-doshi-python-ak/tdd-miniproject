import pytest


class TestRegisterMocking:

    def test_save_user_called_on_success(self, auth, mock_db):
        """DB save must be called when registration succeeds."""
        auth.register("alice", "password123")
        mock_db.save_user.assert_called_once()

    def test_plain_password_never_saved(self, auth, mock_db):
        """Whatever hits the DB must not be the plain password."""
        auth.register("alice", "password123")
        _, saved_password = mock_db.save_user.call_args[0]
        assert saved_password != "password123"

    def test_save_not_called_on_duplicate(self, registered_auth, mock_db):
        """If user exists DB save must be skipped entirely."""
        registered_auth.register("alice", "password123")
        mock_db.save_user.assert_not_called()


class TestLoginMocking:

    def test_db_queried_with_correct_username(self, auth, mock_db):
        """Login must look up the right username in DB."""
        auth.login("alice", "password123")
        mock_db.get_user.assert_called_once_with("alice")

    def test_session_saved_on_successful_login(self, registered_auth, mock_db):
        """Successful login must persist the token in DB."""
        result = registered_auth.login("alice", "password123")
        mock_db.save_session.assert_called_once_with(result["token"], "alice")

    def test_session_not_saved_on_failed_login(self, auth, mock_db):
        """Failed login must never create a session."""
        auth.login("ghost", "wrongpassword")
        mock_db.save_session.assert_not_called()


class TestSessionMocking:

    def test_authenticate_valid_token(self, logged_in_auth, mock_db):
        """Valid token must return the correct username."""
        auth, token = logged_in_auth
        result = auth.authenticate(token)
        assert result["success"] is True
        assert result["username"] == "alice"

    def test_authenticate_invalid_token(self, auth, mock_db):
        """Invalid token must be rejected."""
        mock_db.get_session.return_value = None
        result = auth.authenticate("fake-token")
        assert result["success"] is False
        assert result["message"] == "Invalid or expired token"

    def test_logout_invalidates_session(self, logged_in_auth, mock_db):
        """Logout must delete the session from DB."""
        auth, token = logged_in_auth
        auth.logout(token)
        mock_db.delete_session.assert_called_once_with(token)

    def test_logout_invalid_token_fails(self, auth, mock_db):
        """Logout with bad token must fail gracefully."""
        mock_db.get_session.return_value = None
        result = auth.logout("invalid-token")
        assert result["success"] is False


class TestDBFailure:

    def test_db_down_on_register_raises(self, auth, mock_db):
        """If DB explodes during save — exception bubbles up."""
        mock_db.save_user.side_effect = ConnectionError("DB is down")
        with pytest.raises(ConnectionError, match="DB is down"):
            auth.register("alice", "password123")

    def test_db_down_on_login_raises(self, registered_auth, mock_db):
        """If DB explodes during session save — exception bubbles up."""
        mock_db.save_session.side_effect = ConnectionError("DB is down")
        with pytest.raises(ConnectionError, match="DB is down"):
            registered_auth.login("alice", "password123")
