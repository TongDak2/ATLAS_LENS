from __future__ import annotations

import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_STEALTHMOLE_CONFIG = PROJECT_ROOT.parent / ".stealthmole" / ".env"

# Load local project env if present. Do not require it.
load_dotenv(PROJECT_ROOT / ".env")
# Load StealthMole local secret file if present. Env vars override later via pydantic.
if DEFAULT_STEALTHMOLE_CONFIG.exists():
    load_dotenv(DEFAULT_STEALTHMOLE_CONFIG, override=False)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(PROJECT_ROOT / ".env"), extra="ignore")

    atlas_env: str = "production"
    atlas_allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    atlas_allowed_hosts: str = "localhost,127.0.0.1"
    atlas_max_request_body_bytes: int = 200_000
    atlas_api_key: str = ""
    atlas_docs_enabled: bool = False
    atlas_rate_limit_window_seconds: int = 60
    atlas_rate_limit_requests: int = 30
    atlas_live_rate_limit_requests: int = 10
    stealthmole_async_poll_attempts: int = 2

    stealthmole_config_path: str = str(DEFAULT_STEALTHMOLE_CONFIG)
    stealthmole_base_url: str = "https://hackathon.stealthmole.com"
    stealthmole_access_key: str = ""
    stealthmole_secret_key: str = ""

    openai_api_key: str = ""
    openai_model: str = "gpt-4.1-mini"

    @property
    def allowed_origins(self) -> List[str]:
        return [x.strip() for x in self.atlas_allowed_origins.split(",") if x.strip()]

    @property
    def allowed_hosts(self) -> List[str]:
        return [x.strip() for x in self.atlas_allowed_hosts.split(",") if x.strip()]

    def load_external_stealthmole_env(self) -> None:
        path = Path(self.stealthmole_config_path).expanduser()
        if path.exists():
            load_dotenv(path, override=False)
            self.stealthmole_base_url = os.getenv("STEALTHMOLE_BASE_URL", self.stealthmole_base_url)
            self.stealthmole_access_key = os.getenv("STEALTHMOLE_ACCESS_KEY", self.stealthmole_access_key)
            self.stealthmole_secret_key = os.getenv("STEALTHMOLE_SECRET_KEY", self.stealthmole_secret_key)
            self.atlas_api_key = os.getenv("ATLAS_API_KEY", self.atlas_api_key)


settings = Settings()
settings.load_external_stealthmole_env()
