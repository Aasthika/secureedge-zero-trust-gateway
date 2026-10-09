import jwt

from app.config import settings
from app.security import ALGORITHM


def test_security_headers_are_present(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "permissions-policy" in response.headers


def test_signed_token_with_invalid_subject_is_rejected(client):
    token = jwt.encode(
        {
            "sub": "not-a-user-id",
            "exp": 4102444800,
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401

def test_token_without_expiration_is_rejected(client):
    token = jwt.encode(
        {
            "sub": "1",
            "iat": 1760000000,
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_token_without_issued_at_is_rejected(client):
    token = jwt.encode(
        {
            "sub": "1",
            "exp": 4102444800,
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401


def test_expired_token_is_rejected(client):
    token = jwt.encode(
        {
            "sub": "1",
            "iat": 1600000000,
            "exp": 1600000100,
        },
        settings.secret_key,
        algorithm=ALGORITHM,
    )

    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 401
