from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.main import readiness_check


def test_health_check(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_liveness_check(client):
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


@pytest.mark.anyio
async def test_readiness_check_when_dependencies_are_available():
    with (
        patch("app.main.engine") as mock_engine,
        patch("app.main.redis_client") as mock_redis,
    ):
        mock_redis.ping.return_value = True

        result = await readiness_check()

    assert result == {
        "status": "ready",
        "checks": {
            "database": "available",
            "redis": "available",
        },
    }

    mock_engine.connect.assert_called_once()
    mock_redis.ping.assert_called_once()


@pytest.mark.anyio
async def test_readiness_check_when_redis_is_unavailable():
    with (
        patch("app.main.engine") as mock_engine,
        patch("app.main.redis_client") as mock_redis,
    ):
        mock_redis.ping.return_value = False

        with pytest.raises(HTTPException) as exc_info:
            await readiness_check()

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == {
        "status": "not_ready",
        "checks": {
            "database": "available",
            "redis": "unavailable",
        },
    }

    mock_engine.connect.assert_called_once()
    mock_redis.ping.assert_called_once()


from sqlalchemy.exc import SQLAlchemyError


@pytest.mark.anyio
async def test_readiness_check_when_database_is_unavailable():
    with (
        patch("app.main.engine") as mock_engine,
        patch("app.main.redis_client") as mock_redis,
    ):
        mock_engine.connect.side_effect = SQLAlchemyError("simulated database failure")
        mock_redis.ping.return_value = True

        with pytest.raises(HTTPException) as exc_info:
            await readiness_check()

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == {
        "status": "not_ready",
        "checks": {
            "database": "unavailable",
            "redis": "available",
        },
    }
