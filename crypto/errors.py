"""Исключения криптографического модуля."""

from __future__ import annotations


class CryptoError(Exception):
    """Базовое исключение криптографического слоя."""


class AuthenticationError(CryptoError):
    """Проверка authentication tag не прошла (сообщение изменено/ключ не тот)."""


class NonceReuseError(CryptoError):
    """Обнаружено повторное использование nonce с одним и тем же ключом."""


class KeyConfigurationError(CryptoError):
    """Ключ отсутствует, имеет неверный формат или хранилище повреждено."""


class UnknownKeyError(CryptoError):
    """В сообщении указан key_id, которого нет в хранилище."""

    def __init__(self, key_id: str):
        self.key_id = key_id
        super().__init__(f"unknown key id: {key_id!r}")
