import pytest
from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture(scope="session")
def client():
    """
    TestClient fixture providing an HTTP client to test FastAPI endpoints
    without needing a running live server.
    """
    with TestClient(app) as test_client:
        yield test_client
