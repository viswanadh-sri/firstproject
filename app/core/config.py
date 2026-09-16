from functools import lru_cache

from pydantic import AliasChoices, Field, SecretStr, field_validator
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
    virustotal_api_key: SecretStr | None = None
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    virustotal_timeout_seconds: float = Field(default=120.0, gt=0, le=300)
    virustotal_retry_attempts: int = Field(default=3, ge=0, le=10)
    virustotal_retry_backoff_seconds: float = Field(default=1.0, gt=0, le=30)
    virustotal_poll_interval_seconds: float = Field(default=2.0, gt=0, le=60)
    virustotal_max_poll_seconds: float = Field(default=300.0, gt=0, le=600)
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: SecretStr | None = None
    smtp_from: str = Field(
        default="",
        validation_alias=AliasChoices("SMTP_FROM", "SMTP_FROM_EMAIL"),
    )
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False

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
