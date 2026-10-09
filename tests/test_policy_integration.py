from uuid import uuid4

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models import User
from unittest.mock import patch

from fastapi import HTTPException


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


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("get", "/documents", None),
        (
            "post",
            "/documents",
            {"title": "Policy test", "content": "Test content"},
        ),
    ],
)
def test_document_routes_reject_policy_denial(
    client,
    method,
    path,
    payload,
):
    headers = register_and_login(client)

    with patch("app.dependencies.policy_engine.evaluate") as mock_evaluate:
        mock_evaluate.return_value.allowed = False
        mock_evaluate.return_value.reason = "Test policy denial"

        if payload is None:
            response = getattr(client, method)(
                path,
                headers=headers,
            )
        else:
            response = getattr(client, method)(
                path,
                headers=headers,
                json=payload,
            )

    assert response.status_code == 403
    assert response.json()["detail"] == "Test policy denial"
    mock_evaluate.assert_called_once()


@pytest.mark.parametrize(
    ("method", "payload"),
    [
        ("get", None),
        (
            "put",
            {"title": "Updated title", "content": "Updated content"},
        ),
        ("delete", None),
    ],
)
def test_individual_document_routes_reject_policy_denial(
    client,
    method,
    payload,
):
    headers = register_and_login(client)

    # Create a real document before mocking the policy decision.
    create_response = client.post(
        "/documents",
        headers=headers,
        json={
            "title": "Policy test document",
            "content": "Original content",
        },
    )
    assert create_response.status_code == 201

    document_id = create_response.json()["id"]
    path = f"/documents/{document_id}"

    with patch("app.dependencies.policy_engine.evaluate") as mock_evaluate:
        mock_evaluate.return_value.allowed = False
        mock_evaluate.return_value.reason = "Test policy denial"

        if payload is None:
            response = getattr(client, method)(
                path,
                headers=headers,
            )
        else:
            response = getattr(client, method)(
                path,
                headers=headers,
                json=payload,
            )

    assert response.status_code == 403
    assert response.json()["detail"] == "Test policy denial"
    mock_evaluate.assert_called_once()
