import pytest
from unittest.mock import MagicMock
from src.auth.auth import AuthSystem, DatabaseService

ALICE_HASHED = "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"


@pytest.fixture
def mock_db(mocker):
    """Fake DB — no real database needed."""
    db = mocker.MagicMock(spec=DatabaseService)
    db.get_user.return_value = None      # default: user doesn't exist
    db.get_session.return_value = None   # default: no active session
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
