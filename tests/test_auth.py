from uuid import uuid4
from unittest.mock import patch

import redis
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.database import SessionLocal
from app.dependencies import login_rate_limiter
from app.models import AuditLog


client = TestClient(app)


def test_me_without_token():
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_me_with_invalid_token():
    response = client.get(
        "/auth/me",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert response.status_code == 401


def test_register_login_and_get_me():
    username = f"pytest_user_{uuid4().hex[:8]}"
    password = "SecurePassword123!"

    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    me_response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["username"] == username


def test_normal_user_cannot_access_admin_endpoint(authenticated_client):
    response = authenticated_client.get("/auth/admin-test")
    assert response.status_code == 403


def test_normal_user_cannot_write_users(authenticated_client):
    response = authenticated_client.get("/auth/write-test")
    assert response.status_code == 403


def test_rate_limit_blocks_after_five_requests():
    username = f"rate_limit_{uuid4().hex[:12]}"
    password = "SecurePassword123!"

    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    for _ in range(5):
        response = client.get(
            "/auth/rate-limit-test",
            headers=headers,
        )
        assert response.status_code == 200

    response = client.get(
        "/auth/rate-limit-test",
        headers=headers,
    )
    assert response.status_code == 429


def test_login_rate_limit_returns_429_after_limit():
    # Mock the limiter so this test does not depend on Redis timing
    # or leave rate-limit keys behind for other tests.
    username = f"login_limit_{uuid4().hex[:8]}"

    with patch.object(
        login_rate_limiter,
        "check",
        return_value=(False, 11, 30),
    ) as mock_check:
        response = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": "WrongPassword123!",
            },
        )

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "30"
    assert response.json()["detail"] == ("Too many login attempts. Try again later.")
    mock_check.assert_called_once()


def test_login_rate_limit_returns_503_when_redis_fails():
    with patch.object(
        login_rate_limiter,
        "check",
        side_effect=redis.exceptions.ConnectionError("Redis unavailable"),
    ) as mock_check:
        response = client.post(
            "/auth/login",
            json={
                "username": f"redis_test_{uuid4().hex[:8]}",
                "password": "SecurePassword123!",
            },
        )

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "5"
    assert response.json()["detail"] == ("Login service is temporarily unavailable")
    mock_check.assert_called_once()


def test_authenticated_request_creates_audit_log():
    username = f"audit_test_{uuid4().hex[:8]}"
    password = "SecurePassword123!"

    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200

    db = SessionLocal()
    try:
        audit_log = db.scalar(
            select(AuditLog)
            .where(
                AuditLog.username == username,
                AuditLog.endpoint == "/auth/me",
                AuditLog.method == "GET",
                AuditLog.status_code == 200,
            )
            .order_by(AuditLog.id.desc())
        )

        assert audit_log is not None
        assert audit_log.decision == "ALLOW"
        assert audit_log.username == username
        assert audit_log.endpoint == "/auth/me"
        assert audit_log.method == "GET"
        assert audit_log.status_code == 200
    finally:
        db.close()


def test_unauthenticated_request_creates_deny_audit_log():
    response = client.get("/auth/me")
    assert response.status_code == 401

    db = SessionLocal()
    try:
        audit_log = db.scalar(
            select(AuditLog)
            .where(
                AuditLog.endpoint == "/auth/me",
                AuditLog.method == "GET",
                AuditLog.status_code == 401,
                AuditLog.decision == "DENY",
            )
            .order_by(AuditLog.id.desc())
        )

        assert audit_log is not None
        assert audit_log.decision == "DENY"
        assert audit_log.endpoint == "/auth/me"
        assert audit_log.method == "GET"
        assert audit_log.status_code == 401
    finally:
        db.close()


def test_me_response_does_not_expose_password_hash(authenticated_client):
    response = authenticated_client.get("/auth/me")
    assert response.status_code == 200

    profile = response.json()
    assert "id" in profile
    assert "username" in profile
    assert "email" in profile
    assert "role" in profile
    assert "password_hash" not in profile
    assert "password" not in profile


def test_me_ignores_caller_supplied_user_id(authenticated_client):
    response = authenticated_client.get("/auth/me?user_id=999999999")

    assert response.status_code == 200
    assert response.json()["id"] != 999999999


def test_me_rejects_missing_authorization_header():
    response = client.get("/auth/me")
    assert response.status_code == 401
