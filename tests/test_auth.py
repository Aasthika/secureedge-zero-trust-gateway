from fastapi.testclient import TestClient

from app.main import app

from sqlalchemy import select

from app.database import SessionLocal
from app.models import AuditLog


client = TestClient(app)


def test_me_without_token():
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_me_with_invalid_token():
    response = client.get(
        "/auth/me",
        headers={
            "Authorization": "Bearer invalid-token",
        },
    )

    assert response.status_code == 401


def test_register_login_and_get_me():
    username = "pytest_user"
    password = "SecurePassword123!"

    # Register
    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": "pytest_user@example.com",
            "password": password,
        },
    )

    assert register_response.status_code == 201

    # Login
    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    # Access protected endpoint
    me_response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
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
    username = "rate_limit_user"
    password = "SecurePassword123!"

    # Register user
    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": "rate_limit_user@example.com",
            "password": password,
        },
    )

    assert register_response.status_code == 201

    # Login
    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    headers = {
        "Authorization": f"Bearer {token}",
    }

    # First five requests should be allowed
    for _ in range(5):
        response = client.get(
            "/auth/rate-limit-test",
            headers=headers,
        )

        assert response.status_code == 200

    # Sixth request should be rejected
    response = client.get(
        "/auth/rate-limit-test",
        headers=headers,
    )

    assert response.status_code == 429


def test_authenticated_request_creates_audit_log():
    username = "audit_test_user"
    password = "SecurePassword123!"

    # Register
    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": "audit_test_user@example.com",
            "password": password,
        },
    )

    assert register_response.status_code == 201

    # Login
    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": password,
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    # Make authenticated request
    response = client.get(
        "/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 200

    # Check audit log
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
