"""Управление ключами шифрования.

Источники ключа (в порядке приоритета):

1. Переменная окружения ``APP_ENCRYPTION_KEY`` (base64, 32 байта), загружаемая
   pydantic-settings из локального ``.env``. Это «внешний источник» ключа,
   требуемый ЛР3; ``.env`` исключён из Git.
2. Локальное хранилище ``keys/keyring.json`` (тоже исключено из Git) —
   здесь хранятся ключи, выведенные из эксплуатации после ротации.
3. Если ключа нет нигде, новый ключ генерируется криптографически стойким
   ``os.urandom`` и сохраняется в keyring. Такой режим удобен для первого
   запуска, но в отчёте следует использовать вариант с ``.env``.

Ключ никогда не попадает в журналы: наружу отдаются только ``key_id`` и
короткий SHA-256 отпечаток (не позволяющий восстановить ключ).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import Settings, get_settings
from crypto.constants import KEY_SIZE
from crypto.errors import KeyConfigurationError, UnknownKeyError

logger = logging.getLogger(__name__)


def encode_key(key: bytes) -> str:
    """Кодирует ключ в base64 (для .env / keyring)."""
    return base64.b64encode(key).decode("ascii")


def decode_key(value: str) -> bytes:
    """Декодирует и проверяет base64-ключ длиной 32 байта."""
    text = value.strip()
    if text.startswith("base64:"):
        text = text[len("base64:"):]
    try:
        key = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyConfigurationError(
            "APP_ENCRYPTION_KEY должен быть корректным base64"
        ) from exc
    return _validate_key(key)


def key_fingerprint(key: bytes, size: int = 8) -> str:
    """Короткий отпечаток ключа для журнала (не раскрывает ключ)."""
    return hashlib.sha256(key).hexdigest()[:size]


def _validate_key(key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise KeyConfigurationError(
            f"длина ключа должна быть {KEY_SIZE} байт (256 бит), "
            f"получено {len(key)}"
        )
    return key


class KeyManager:
    """Хранилище ключей с поддержкой ротации.

    Экземпляр потокобезопасен: ключи читаются и изменяются под блокировкой.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        persist_missing_key: bool = True,
    ) -> None:
        self._settings = settings or get_settings()
        self._lock = threading.RLock()
        self._keys: dict[str, bytes] = {}
        self._current: str | None = None
        self._persist = persist_missing_key
        self._load()

    # ── Конструкторы ─────────────────────────────────────────────────────

    @classmethod
    def from_key(cls, key: bytes, key_id: str = "key-test") -> "KeyManager":
        """Создаёт менеджер из готового ключа (удобно в тестах)."""
        self = cls.__new__(cls)
        self._settings = None
        self._lock = threading.RLock()
        self._persist = False
        self._keys = {key_id: _validate_key(key)}
        self._current = key_id
        return self

    # ── Загрузка / сохранение ────────────────────────────────────────────

    def _load(self) -> None:
        assert self._settings is not None

        keyring = self._read_keyring()
        for key_id, encoded in (keyring.get("keys") or {}).items():
            self._keys[str(key_id)] = decode_key(str(encoded))

        secret = self._settings.encryption_key
        keyring_current = keyring.get("current")

        if secret is not None:
            # .env — внешний источник ключа; он имеет приоритет.
            self._keys[self._settings.key_id] = decode_key(
                secret.get_secret_value()
            )
            self._current = self._settings.key_id
        elif isinstance(keyring_current, str) and keyring_current in self._keys:
            self._current = keyring_current
        else:
            # Ни .env, ни keyring — генерируем ключ и сохраняем локально.
            key_id = self._settings.key_id
            key = _validate_key(os.urandom(KEY_SIZE))
            self._keys[key_id] = key
            self._current = key_id
            logger.warning(
                "Ключ не найден в конфигурации: сгенерирован новый "
                "key_id=%s fingerprint=%s. Запустите scripts/generate_key.py, "
                "чтобы сохранить его в .env.",
                key_id,
                key_fingerprint(key),
            )
            if self._persist:
                self._save_keyring()

        logger.info(
            "KeyManager готов: key_id=%s fingerprint=%s known_key_ids=%s",
            self._current,
            self.fingerprint(),
            sorted(self._keys),
        )

    def _read_keyring(self) -> dict[str, Any]:
        assert self._settings is not None
        path = Path(self._settings.keyring_file)
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyConfigurationError(
                f"не удалось прочитать хранилище ключей {path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise KeyConfigurationError(
                f"некорректный формат хранилища ключей {path}"
            )
        return data

    def _save_keyring(self) -> None:
        assert self._settings is not None
        path = Path(self._settings.keyring_file)
        path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "version": 1,
            "current": self._current,
            "keys": {
                key_id: encode_key(key)
                for key_id, key in self._keys.items()
            },
        }
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        try:
            os.chmod(tmp, 0o600)  # на Windows вызов может быть ограничен
        except OSError:
            pass
        os.replace(tmp, path)

    # ── Доступ к ключам ──────────────────────────────────────────────────

    @property
    def current_key_id(self) -> str:
        with self._lock:
            if self._current is None:
                raise KeyConfigurationError("текущий ключ не инициализирован")
            return self._current

    def key_for(self, key_id: str | None = None) -> bytes:
        """Возвращает ключ по key_id (по умолчанию — текущий)."""
        resolved = key_id or self.current_key_id
        with self._lock:
            key = self._keys.get(resolved)
        if key is None:
            raise UnknownKeyError(resolved)
        return key

    def has_key(self, key_id: str) -> bool:
        with self._lock:
            return key_id in self._keys

    @property
    def known_key_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._keys)

    def fingerprint(self, key_id: str | None = None, size: int = 8) -> str:
        return key_fingerprint(self.key_for(key_id), size=size)

    def describe(self) -> dict[str, Any]:
        """Безопасная для журнала информация о текущем ключе."""
        return {
            "algorithm": "AES-256-GCM",
            "key_id": self.current_key_id,
            "key_fingerprint": self.fingerprint(),
            "known_key_ids": self.known_key_ids,
        }

    # ── Ротация ──────────────────────────────────────────────────────────

    def rotate(self, new_key_id: str | None = None) -> str:
        """Генерирует новый ключ и делает его текущим.

        Старые ключи остаются в хранилище, чтобы можно было расшифровать
        сообщения, отправленные до ротации. Возвращает новый key_id.
        """
        new_key_id = new_key_id or _default_key_id()
        with self._lock:
            if new_key_id in self._keys:
                raise KeyConfigurationError(
                    f"key_id {new_key_id!r} уже существует"
                )
            key = _validate_key(os.urandom(KEY_SIZE))
            self._keys[new_key_id] = key
            self._current = new_key_id
            if self._persist and self._settings is not None:
                self._save_keyring()
            fingerprint = key_fingerprint(key)

        # В журнал попадает только идентификатор и отпечаток, не ключ.
        logger.info(
            "Выполнена ротация ключа: new_key_id=%s fingerprint=%s",
            new_key_id,
            fingerprint,
        )
        return new_key_id


def _default_key_id() -> str:
    return f"key-{datetime.now(timezone.utc):%Y-%m}"
