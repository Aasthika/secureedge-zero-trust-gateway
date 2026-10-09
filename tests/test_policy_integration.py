from uuid import uuid4

from sqlalchemy import select

from app.database import SessionLocal
from app.models import User


def register_and_login(client, role="user"):
    unique_id = uuid4().hex[:12]
    username = f"policy_{unique_id}"
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

    # Set up the test role directly in the test database.
    # The public registration endpoint must not accept arbitrary roles.
    if role != "user":
        db = SessionLocal()
        try:
            user = db.scalar(select(User).where(User.username == username))
            assert user is not None
            user.role = role
            db.commit()
        finally:
            db.close()

    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    return {
        "Authorization": f"Bearer {token}",
    }


def test_analyst_can_read_analytics(client):
    headers = register_and_login(client, role="analyst")

    response = client.get(
        "/auth/analytics-test",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["role"] == "analyst"


def test_normal_user_cannot_read_analytics(client):
    headers = register_and_login(client, role="user")

    response = client.get(
        "/auth/analytics-test",
        headers=headers,
    )

    assert response.status_code == 403


def test_unauthenticated_user_cannot_read_analytics(client):
    response = client.get("/auth/analytics-test")

    assert response.status_code == 401
