from fastapi.testclient import TestClient

from app.main import app
from app.metrics import http_requests_total
from app.metrics import rate_limited_requests_total

client = TestClient(app)


def test_http_request_counter_increments():
    before = http_requests_total.labels(
        method="GET",
        status="200",
    )._value.get()

    response = client.get("/health")

    assert response.status_code == 200

    after = http_requests_total.labels(
        method="GET",
        status="200",
    )._value.get()

    assert after == before + 1


def test_rate_limited_counter_increments():
    username = "metrics_rate_user"
    password = "SecurePassword123!"

    # Register
    register_response = client.post(
        "/auth/register",
        json={
            "username": username,
            "email": "metrics_rate_user@example.com",
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

    # Consume the five allowed requests.
    for _ in range(5):
        response = client.get(
            "/auth/rate-limit-test",
            headers=headers,
        )

        assert response.status_code == 200

    # Capture metric before the rejected request.
    before = rate_limited_requests_total._value.get()

    # Sixth request should be rejected.
    response = client.get(
        "/auth/rate-limit-test",
        headers=headers,
    )

    assert response.status_code == 429

    # Counter should increase by one.
    after = rate_limited_requests_total._value.get()

    assert after == before + 1
