import pytest
from src.auth.auth import AuthSystem

# fixture chaining 

@pytest.fixture(scope="function")
def auth():
    """
    Fresh AuthSystem for every test.
    """
    return AuthSystem()


@pytest.fixture(scope="function")
def registered_auth(auth):
    """
    AuthSystem with alice already registered.
    Fixtures can depend on other fixtures!
    """
    auth.register("alice", "password123")
    return auth


@pytest.fixture(scope="function")
def logged_in_auth(registered_auth):
    """
    AuthSystem with alice registered AND logged in.
    Returns tuple of (auth, token) — tests get both.
    Fixtures can be chained like lego blocks!
    """
    result = registered_auth.login("alice", "password123")
    token = result["token"]
    return registered_auth, token













# ─────────────────────────────────────
# SCOPE EXPLAINED:
#
# scope="function" → fresh fixture every test  (default)
# scope="class"    → shared within a test class
# scope="module"   → shared within a test file
# scope="session"  → shared across ALL tests
# ─────────────────────────────────────