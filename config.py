"""Конфигурация приложения на основе pydantic-settings.

Все параметры читаются из переменных окружения с префиксом ``APP_``
и/или из локального файла ``.env``. Файл ``.env`` содержит секрет и
поэтому исключён из Git; в репозитории хранится только ``.env.example``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """Параметры клиента и сервера."""

    model_config = SettingsConfigDict(
        env_prefix="APP_",
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    host: str = "127.0.0.1"
    # 0 допустим: сервер/тесты могут занять произвольный свободный порт.
    port: int = Field(default=65432, ge=0, le=65535)

    # ── Ключ шифрования ──────────────────────────────────────────────────
    # SecretStr не раскрывает значение в repr()/логах.
    encryption_key: SecretStr | None = None
    key_id: str = "key-2026-01"
    keyring_file: Path = PROJECT_ROOT / "keys" / "keyring.json"

    # ── Протокол и сеть ──────────────────────────────────────────────────
    timeout_seconds: float = Field(default=5.0, gt=0)
    max_retries: int = Field(default=3, ge=1, le=10)
    max_message_bytes: int = Field(default=64 * 1024, ge=1024, le=16 * 1024 * 1024)
    strict_nonce_check: bool = True
    slow_test_seconds: float = Field(default=30.0, ge=0)

    log_dir: Path = PROJECT_ROOT / "logs"

    @field_validator("keyring_file", "log_dir", mode="before")
    @classmethod
    def _resolve_path(cls, value: Any) -> Any:
        """Относительные пути трактуются от корня проекта, а не от CWD."""
        if value is None:
            return value
        path = Path(value)
        return path if path.is_absolute() else PROJECT_ROOT / path

    def safe_summary(self) -> dict[str, Any]:
        """Сводка настроек без секретов — безопасна для журнала."""
        return {
            "host": self.host,
            "port": self.port,
            "key_id": self.key_id,
            "key_configured": self.encryption_key is not None,
            "max_message_bytes": self.max_message_bytes,
            "strict_nonce_check": self.strict_nonce_check,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Кешированный экземпляр настроек (читает .env один раз)."""
    return Settings()
