"""Application settings loaded from environment variables."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the QRoulette backend."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "QRoulette API"
    app_env: str = "development"
    app_version: str = "0.1.0"
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["*"])
    http_timeout_seconds: float = 15.0

    gemini_api_key: str = ""
    google_safe_browsing_api_key: str = ""
    whois_xml_api_key: str = ""
    redirect_chain_api_key: str = ""
    supabase_url: str = ""
    supabase_key: str = ""
    supabase_service_role_key: str = ""


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings instance."""

    return Settings()
