import redis

from fastapi import HTTPException

from app.dependencies import enforce_rate_limit, rate_limiter
from app.models import User


def test_rate_limiter_fails_closed_when_redis_is_unavailable(
    monkeypatch,
):
    def unavailable(_key):
        raise redis.exceptions.ConnectionError("Redis unavailable")

    monkeypatch.setattr(rate_limiter, "check", unavailable)

    user = User(
        id=987654,
        username="redis_failure_test",
        email="redis_failure_test@example.com",
        role="user",
        password_hash="not-used",
    )

    try:
        enforce_rate_limit(current_user=user)
        assert False, "Expected rate limiter to reject the request"
    except HTTPException as exc:
        assert exc.status_code == 503
        assert exc.headers["Retry-After"] == "5"
