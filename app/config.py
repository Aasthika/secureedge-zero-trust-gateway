from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SecureEdge"
    app_version: str = "0.1.0"
    environment: str = "development"

    database_url: str = Field(min_length=1)
    redis_url: str = Field(min_length=1)
    secret_key: str = Field(min_length=32)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("database_url", "redis_url", "secret_key")
    @classmethod
    def reject_placeholder_values(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Configuration value must not be empty")

        if value.lower().startswith("your-"):
            raise ValueError("Replace placeholder configuration values")

        return value

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        allowed = {"development", "testing", "staging", "production"}
        value = value.strip().lower()

        if value not in allowed:
            raise ValueError("Unsupported environment")

        return value

    @model_validator(mode="after")
    def validate_production_secret(self):
        if self.environment == "production":
            secret = self.secret_key.lower()

            placeholders = (
                "replace-this",
                "change-me",
                "your-",
                "test-only",
                "development-secret",
                "example-secret",
            )

            if any(value in secret for value in placeholders):
                raise ValueError("Production requires a securely generated secret key")

        return self


settings = Settings()
