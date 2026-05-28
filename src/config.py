"""Centralized configuration via Pydantic Settings."""

from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # OmniRoute AI Gateway
    omniroute_base_url: str = "http://localhost:3000/v1"
    omniroute_api_key: str = ""

    # OpenAI (direct fallback)
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"

    # Breach / Leak data sources
    hibp_api_key: str = ""
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    whoisxml_api_key: str = ""
    chiasmodon_token: str = ""
    dehashed_api_key: str = ""
    scylla_api_key: str = ""
    leakcheck_api_key: str = ""
    breachdirectory_api_key: str = ""
    snusbase_api_key: str = ""
    intelx_api_key: str = ""

    # GitHub
    github_token: str = ""

    # ZKIT
    zkit_salt: str = ""

    # Telegram alerts
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    # Webhook alerts
    webhook_url: Optional[str] = None

    # Scanner settings
    scanner_workers: int = 20
    scanner_mode: str = "targeted"

    # Application settings
    log_level: str = "INFO"
    cache_dir: str = ".osint_cache"
    rate_limit_file: str = ".osint_rate_limit.json"

    @property
    def project_root(self) -> Path:
        """Return the project root directory."""
        return Path(__file__).parent.parent

    @property
    def cache_path(self) -> Path:
        """Return the cache directory path."""
        path = Path(self.cache_dir)
        if not path.is_absolute():
            path = self.project_root / path
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def effective_openai_base_url(self) -> str:
        """Return OmniRoute base URL if configured, else direct OpenAI."""
        if self.omniroute_api_key or self.omniroute_base_url != "http://localhost:3000/v1":
            return self.omniroute_base_url
        return self.openai_base_url

    @property
    def effective_openai_api_key(self) -> str:
        """Return OmniRoute API key if configured, else direct OpenAI key."""
        if self.omniroute_api_key:
            return self.omniroute_api_key
        return self.openai_api_key


# Singleton settings instance
settings = Settings()
