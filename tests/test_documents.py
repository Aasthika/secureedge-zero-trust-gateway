import uuid

import pytest


def register_and_login(client):
    unique_id = uuid.uuid4().hex
    username = f"document_user_{unique_id}"

    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "SecurePassword123!",
        },
    )
    assert register_response.status_code == 201

    login_response = client.post(
        "/auth/login",
        json={
            "username": username,
            "password": "SecurePassword123!",
        },
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def create_document(client, headers, title="Test document"):
    return client.post(
        "/documents",
        headers=headers,
        json={
            "title": title,
            "content": "Confidential test content",
        },
    )


def test_create_document_assigns_authenticated_owner(client):
    headers = register_and_login(client)

    me_response = client.get("/auth/me", headers=headers)
    assert me_response.status_code == 200
    user_id = me_response.json()["id"]

    response = client.post(
        "/documents",
        headers=headers,
        json={
            "title": "Ownership test",
            "content": "Document content",
            "owner_id": 999999,
        },
    )

    assert response.status_code == 201
    assert response.json()["owner_id"] == user_id
    assert response.json()["title"] == "Ownership test"


def test_user_can_list_only_their_documents(client):
    first_user = register_and_login(client)
    second_user = register_and_login(client)

    first_response = create_document(client, first_user, "First user's document")
    second_response = create_document(client, second_user, "Second user's document")

    assert first_response.status_code == 201
    assert second_response.status_code == 201

    response = client.get("/documents", headers=first_user)

    assert response.status_code == 200
    titles = [document["title"] for document in response.json()]
    assert "First user's document" in titles
    assert "Second user's document" not in titles


def test_owner_can_read_their_document(client):
    headers = register_and_login(client)
    create_response = create_document(client, headers)

    assert create_response.status_code == 201
    document_id = create_response.json()["id"]

    response = client.get(
        f"/documents/{document_id}",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == document_id


def test_user_cannot_read_another_users_document(client):
    first_user = register_and_login(client)
    second_user = register_and_login(client)

    create_response = create_document(client, first_user)
    assert create_response.status_code == 201

    document_id = create_response.json()["id"]

    response = client.get(
        f"/documents/{document_id}",
        headers=second_user,
    )

    assert response.status_code == 404


def test_nonexistent_document_returns_404(client):
    headers = register_and_login(client)

    response = client.get(
        "/documents/999999999",
        headers=headers,
    )

    assert response.status_code == 404


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("get", "/documents", None),
        (
            "post",
            "/documents",
            {"title": "Unauthenticated", "content": "Test"},
        ),
    ],
)
def test_document_endpoints_require_authentication(client, method, path, payload):
    if payload is None:
        response = getattr(client, method)(path)
    else:
        response = getattr(client, method)(path, json=payload)

    assert response.status_code == 401
