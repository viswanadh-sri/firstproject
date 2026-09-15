from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Secure FastAPI Auth"
    environment: str = "development"
    mongodb_uri: SecretStr = Field(
        default=SecretStr("mongodb://localhost:27017"),
        description="MongoDB Atlas connection string",
    )
    mongodb_database: str = "fastapi_auth"
    jwt_secret_key: SecretStr = Field(
        default=SecretStr("change-this-development-secret-key"),
        min_length=32,
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=30, ge=1, le=1440)
    password_reset_expire_minutes: int = Field(default=30, ge=1, le=1440)
    cookie_secure: bool = False
    cookie_domain: str | None = None
    allowed_origins: str = "http://localhost:8000"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("environment")
    @classmethod
    def normalize_environment(cls, value: str) -> str:
        return value.strip().lower()

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
