import pytest
from pydantic import ValidationError

from app.config import Settings


def make_settings(**overrides):
    values = {
        "app_name": "SecureEdge",
        "app_version": "0.1.0",
        "environment": "development",
        "database_url": "sqlite:///./test.db",
        "redis_url": "redis://localhost:6379/0",
        "secret_key": "a-valid-test-secret-key-with-more-than-32-chars",
    }
    values.update(overrides)
    return Settings(**values)


def test_development_allows_test_secret():
    settings = make_settings()
    assert settings.environment == "development"


@pytest.mark.parametrize(
    "secret",
    [
        "replace-this-with-a-random-secret-key-of-at-least-32-characters",
        "change-me-to-a-secure-production-secret-key",
        "test-only-secret-key-for-production-environment",
        "example-secret-key-that-is-long-enough-for-validation",
    ],
)
def test_production_rejects_placeholder_secrets(secret):
    with pytest.raises(ValidationError):
        make_settings(environment="production", secret_key=secret)


def test_production_accepts_non_placeholder_secret():
    settings = make_settings(
        environment="production",
        secret_key="a-unique-random-looking-secret-key-with-over-32-chars",
    )
    assert settings.environment == "production"
