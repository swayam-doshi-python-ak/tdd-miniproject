import pytest
from src.auth.auth import AuthSystem, DatabaseService

ALICE_HASHED = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"


@pytest.fixture
def mock_db(mocker):
    """Fake DB — no real database needed."""
    db = mocker.MagicMock(spec=DatabaseService)
    db.get_user.return_value = None
    db.get_session.return_value = None
    return db


@pytest.fixture
def auth(mock_db):
    """AuthSystem wired to fake DB."""
    return AuthSystem(db=mock_db)


@pytest.fixture
def registered_auth(auth, mock_db):
    """AuthSystem with alice already in the DB."""
    mock_db.get_user.return_value = {
        "username": "alice",
        "password": ALICE_HASHED
    }
    return auth


@pytest.fixture
def logged_in_auth(registered_auth, mock_db):
    """
    AuthSystem with alice registered AND logged in.
    Returns (auth, token) — tests that need the token get both.
    """
    result = registered_auth.login("alice", "password123")
    token = result["token"]
    mock_db.get_session.return_value = "alice"
    return registered_auth, token
