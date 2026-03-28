"""Application settings loaded from environment variables."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[3]
BACKEND_DIR = ROOT_DIR / "backend"


class Settings(BaseSettings):
    """Runtime configuration for the QRoulette backend."""

    model_config = SettingsConfigDict(
        env_file=(ROOT_DIR / ".env", BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = Field(default="QRoulette API", validation_alias="APP_NAME")
    app_env: str = Field(default="development", validation_alias="APP_ENV")
    app_version: str = Field(default="0.1.0", validation_alias="APP_VERSION")
    app_host: str = Field(default="0.0.0.0", validation_alias="APP_HOST")
    app_port: int = Field(default=8000, validation_alias="APP_PORT")
    api_prefix: str = Field(default="/api", validation_alias="API_PREFIX")
    log_level: str = Field(default="INFO", validation_alias="LOG_LEVEL")
    cors_allow_origins: list[str] = Field(
        default_factory=lambda: ["*"],
        validation_alias="CORS_ALLOW_ORIGINS",
    )
    http_timeout_seconds: float = Field(
        default=15.0,
        ge=1.0,
        validation_alias="HTTP_TIMEOUT_SECONDS",
    )
    safe_browsing_base_url: str = Field(
        default="https://safebrowsing.googleapis.com",
        validation_alias="SAFE_BROWSING_BASE_URL",
    )
    safe_browsing_timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        validation_alias="SAFE_BROWSING_TIMEOUT_SECONDS",
    )

    gemini_api_key: str = Field(default="", validation_alias="GEMINI_API_KEY")
    gemini_base_url: str = Field(
        default="https://generativelanguage.googleapis.com/v1beta",
        validation_alias="GEMINI_BASE_URL",
    )
    gemini_model: str = Field(
        default="gemini-2.5-flash",
        validation_alias="GEMINI_MODEL",
    )
    gemini_timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        validation_alias="GEMINI_TIMEOUT_SECONDS",
    )
    google_safe_browsing_api_key: str = Field(
        default="",
        validation_alias="GOOGLE_SAFE_BROWSING_API_KEY",
    )
    whois_xml_api_key: str = Field(default="", validation_alias="WHOIS_XML_API_KEY")
    whois_base_url: str = Field(
        default="https://www.whoisxmlapi.com/whoisserver/WhoisService",
        validation_alias="WHOIS_BASE_URL",
    )
    whois_timeout_seconds: float = Field(
        default=8.0,
        ge=1.0,
        validation_alias="WHOIS_TIMEOUT_SECONDS",
    )
    reputation_api_key: str = Field(default="", validation_alias="REPUTATION_API_KEY")
    reputation_base_url: str = Field(
        default="",
        validation_alias="REPUTATION_BASE_URL",
    )
    reputation_timeout_seconds: float = Field(
        default=8.0,
        ge=1.0,
        validation_alias="REPUTATION_TIMEOUT_SECONDS",
    )
    threat_intel_api_key: str = Field(
        default="",
        validation_alias="THREAT_INTEL_API_KEY",
    )
    threat_intel_base_url: str = Field(
        default="",
        validation_alias="THREAT_INTEL_BASE_URL",
    )
    threat_intel_timeout_seconds: float = Field(
        default=8.0,
        ge=1.0,
        validation_alias="THREAT_INTEL_TIMEOUT_SECONDS",
    )
    ssl_info_api_key: str = Field(default="", validation_alias="SSL_INFO_API_KEY")
    ssl_info_base_url: str = Field(default="", validation_alias="SSL_INFO_BASE_URL")
    ssl_info_timeout_seconds: float = Field(
        default=8.0,
        ge=1.0,
        validation_alias="SSL_INFO_TIMEOUT_SECONDS",
    )
    redirect_chain_api_key: str = Field(
        default="",
        validation_alias="REDIRECT_CHAIN_API_KEY",
    )
    redirects_timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        validation_alias="REDIRECTS_TIMEOUT_SECONDS",
    )
    supabase_url: str = Field(default="", validation_alias="SUPABASE_URL")
    supabase_key: str = Field(default="", validation_alias="SUPABASE_KEY")
    supabase_service_role_key: str = Field(
        default="",
        validation_alias="SUPABASE_SERVICE_ROLE_KEY",
    )

    @field_validator("cors_allow_origins", mode="before")
    @classmethod
    def parse_cors_allow_origins(cls, value: object) -> object:
        """Support comma-separated CORS origins in env vars."""

        if isinstance(value, str) and not value.startswith("["):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()
