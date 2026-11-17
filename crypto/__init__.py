"""Криптографический слой: AES-256-GCM и управление ключами."""

from crypto.constants import ALGORITHM, KEY_SIZE, NONCE_SIZE, TAG_SIZE
from crypto.crypto_service import CryptoService, NonceTracker, SealedPayload
from crypto.errors import (
    AuthenticationError,
    CryptoError,
    KeyConfigurationError,
    NonceReuseError,
    UnknownKeyError,
)
from crypto.key_manager import KeyManager, decode_key, encode_key, key_fingerprint

__all__ = [
    "ALGORITHM",
    "KEY_SIZE",
    "NONCE_SIZE",
    "TAG_SIZE",
    "CryptoService",
    "NonceTracker",
    "SealedPayload",
    "CryptoError",
    "AuthenticationError",
    "NonceReuseError",
    "KeyConfigurationError",
    "UnknownKeyError",
    "KeyManager",
    "decode_key",
    "encode_key",
    "key_fingerprint",
]
