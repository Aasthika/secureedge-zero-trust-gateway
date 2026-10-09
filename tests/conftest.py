import os

# Set test configuration before importing application modules.
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = "secureedge-test-only-secret-key-not-for-production-123456"
os.environ["ENVIRONMENT"] = "testing"
os.environ["REDIS_URL"] = "redis://localhost:6379/15"

import pytest
from fastapi.testclient import TestClient

from app.database import engine
from app.main import app
from app.models import Base
from app.redis_client import redis_client


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    # Clear only rate-limit keys from the dedicated test Redis database.
    for key in redis_client.scan_iter(match="rate_limit:user:*"):
        redis_client.delete(key)

    # Recreate the test database.
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield

    # Clean up the test database after the test session.
    Base.metadata.drop_all(bind=engine)
    redis_client.close()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def authenticated_client(client):
    from uuid import uuid4

    unique_id = uuid4().hex
    username = f"fixture_user_{unique_id}"
    email = f"{username}@example.com"
    password = "SecurePassword123!"

    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password,
        },
    )

    assert register_response.status_code == 201

    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    client.headers.update({"Authorization": f"Bearer {token}"})

    return client
