"""Тесты криптографического модуля AES-256-GCM (требования ЛР3)."""

from __future__ import annotations

import base64
import os

import pytest

from config import Settings
from crypto.constants import KEY_SIZE, NONCE_SIZE, TAG_SIZE
from crypto.crypto_service import CryptoService, NonceTracker
from crypto.errors import (
    AuthenticationError,
    KeyConfigurationError,
    NonceReuseError,
)
from crypto.key_manager import (
    KeyManager,
    decode_key,
    encode_key,
    key_fingerprint,
)

PLAINTEXT = b'{"type":"TRANSFER","payload":{"amount":500.0}}'
AAD = b"BSP1-test-header"


# ─────────────────────────────────────────────────────────────────────────────
# Тест 1: encrypt → decrypt → original message
# ─────────────────────────────────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip(crypto: CryptoService) -> None:
    sealed = crypto.encrypt(PLAINTEXT, aad=AAD)
    decrypted = crypto.decrypt(
        sealed.nonce, sealed.ciphertext, sealed.tag, aad=AAD
    )
    assert decrypted == PLAINTEXT


def test_roundtrip_binary_payload(crypto: CryptoService) -> None:
    payload = os.urandom(4096)
    sealed = crypto.encrypt(payload)
    assert crypto.decrypt(sealed.nonce, sealed.ciphertext, sealed.tag) == payload


# ─────────────────────────────────────────────────────────────────────────────
# Тест 2: изменение ciphertext → authentication failure
# ─────────────────────────────────────────────────────────────────────────────

def test_modified_ciphertext_is_rejected(crypto: CryptoService) -> None:
    sealed = crypto.encrypt(PLAINTEXT, aad=AAD)
    damaged = bytearray(sealed.ciphertext)
    damaged[len(damaged) // 2] ^= 0x01

    with pytest.raises(AuthenticationError):
        crypto.decrypt(sealed.nonce, bytes(damaged), sealed.tag, aad=AAD)


def test_modified_tag_is_rejected(crypto: CryptoService) -> None:
    sealed = crypto.encrypt(PLAINTEXT)
    damaged_tag = bytes([sealed.tag[0] ^ 0x01]) + sealed.tag[1:]

    with pytest.raises(AuthenticationError):
        crypto.decrypt(sealed.nonce, sealed.ciphertext, damaged_tag)


def test_modified_nonce_is_rejected(crypto: CryptoService) -> None:
    sealed = crypto.encrypt(PLAINTEXT)

    with pytest.raises(AuthenticationError):
        crypto.decrypt(
            os.urandom(NONCE_SIZE), sealed.ciphertext, sealed.tag
        )


def test_modified_aad_is_rejected(crypto: CryptoService) -> None:
    sealed = crypto.encrypt(PLAINTEXT, aad=AAD)

    with pytest.raises(AuthenticationError):
        crypto.decrypt(
            sealed.nonce,
            sealed.ciphertext,
            sealed.tag,
            aad=b"BSP1-other-header",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Тест 3: неправильный ключ → ошибка
# ─────────────────────────────────────────────────────────────────────────────

def test_wrong_key_is_rejected(crypto: CryptoService) -> None:
    sealed = crypto.encrypt(PLAINTEXT, aad=AAD)

    other_service = CryptoService(
        KeyManager.from_key(os.urandom(KEY_SIZE), "key-test")
    )
    with pytest.raises(AuthenticationError):
        other_service.decrypt(
            sealed.nonce, sealed.ciphertext, sealed.tag, aad=AAD
        )


# ─────────────────────────────────────────────────────────────────────────────
# Тест 4: разные nonce для последовательных сообщений
# ─────────────────────────────────────────────────────────────────────────────

def test_nonce_is_unique_per_message(crypto: CryptoService) -> None:
    sealed = [crypto.encrypt(PLAINTEXT) for _ in range(500)]
    nonces = [item.nonce for item in sealed]

    assert len(set(nonces)) == len(nonces)
    assert all(len(nonce) == NONCE_SIZE for nonce in nonces)
    # Одинаковый plaintext даёт разные ciphertext благодаря разным nonce.
    assert len({item.ciphertext for item in sealed}) == len(sealed)


def test_nonce_reuse_on_encrypt_is_detected(crypto: CryptoService) -> None:
    nonce = os.urandom(NONCE_SIZE)
    crypto.encrypt(PLAINTEXT, nonce=nonce)

    with pytest.raises(NonceReuseError):
        crypto.encrypt(PLAINTEXT, nonce=nonce)


def test_fixed_zero_nonce_is_detected(crypto: CryptoService) -> None:
    zero_nonce = b"\x00" * NONCE_SIZE
    crypto.encrypt(PLAINTEXT, nonce=zero_nonce)

    with pytest.raises(NonceReuseError):
        crypto.encrypt(PLAINTEXT, nonce=zero_nonce)


def test_replayed_message_is_detected(crypto: CryptoService) -> None:
    sealed = crypto.encrypt(PLAINTEXT)
    crypto.decrypt(sealed.nonce, sealed.ciphertext, sealed.tag)

    with pytest.raises(NonceReuseError):
        crypto.decrypt(sealed.nonce, sealed.ciphertext, sealed.tag)


def test_nonce_tracker_can_be_disabled() -> None:
    service = CryptoService(
        KeyManager.from_key(os.urandom(KEY_SIZE)),
        strict_nonce_check=False,
    )
    nonce = os.urandom(NONCE_SIZE)
    first = service.encrypt(PLAINTEXT, nonce=nonce)
    second = service.encrypt(PLAINTEXT, nonce=nonce)

    assert first.nonce == second.nonce
    assert isinstance(service._outgoing_nonces, NonceTracker)  # noqa: SLF001


def test_format_sizes(crypto: CryptoService) -> None:
    sealed = crypto.encrypt(PLAINTEXT)
    assert len(sealed.nonce) == 12
    assert len(sealed.tag) == 16
    assert crypto.algorithm == "AES-256-GCM"


# ─────────────────────────────────────────────────────────────────────────────
# Управление ключами
# ─────────────────────────────────────────────────────────────────────────────

def test_key_from_env(settings: Settings) -> None:
    manager = KeyManager(settings)
    assert manager.current_key_id == "key-test"
    assert len(manager.key_for()) == KEY_SIZE
    assert manager.key_for() == bytes(range(32))


def test_key_is_not_leaked_in_repr(settings: Settings) -> None:
    manager = KeyManager(settings)
    description = manager.describe()
    key_hex = manager.key_for().hex()

    assert description["key_id"] == "key-test"
    assert description["key_fingerprint"] == key_fingerprint(
        manager.key_for()
    )
    assert key_hex not in repr(description)
    assert key_hex not in repr(manager.key_for())


def test_decode_key_validation() -> None:
    with pytest.raises(KeyConfigurationError):
        decode_key(base64.b64encode(b"short").decode())

    with pytest.raises(KeyConfigurationError):
        decode_key("not-base64!!!")

    key = os.urandom(KEY_SIZE)
    assert decode_key(encode_key(key)) == key


def test_generated_key_is_persisted(tmp_path) -> None:
    keyring = tmp_path / "keyring.json"
    settings = Settings(
        _env_file=None,
        encryption_key=None,
        key_id="key-auto",
        keyring_file=keyring,
        log_dir=tmp_path / "logs",
    )

    first = KeyManager(settings)
    key = first.key_for(first.current_key_id)
    assert keyring.exists()
    assert len(key) == KEY_SIZE

    second = KeyManager(settings)
    assert second.current_key_id == first.current_key_id
    assert second.key_for(second.current_key_id) == key


def test_key_rotation_keeps_old_key(tmp_path) -> None:
    keyring = tmp_path / "keyring.json"
    settings = Settings(
        _env_file=None,
        encryption_key=None,
        key_id="key-1",
        keyring_file=keyring,
        log_dir=tmp_path / "logs",
    )
    manager = KeyManager(settings)
    old_key_id = manager.current_key_id
    old_key = manager.key_for(old_key_id)

    new_key_id = manager.rotate("key-2")
    new_key = manager.key_for(new_key_id)

    assert new_key_id == "key-2"
    assert new_key != old_key
    assert manager.key_for(old_key_id) == old_key

    reopened = KeyManager(settings)
    assert reopened.current_key_id == "key-2"
    assert reopened.key_for("key-1") == old_key
    assert reopened.key_for("key-2") == new_key


def test_stale_key_can_decrypt_old_message(tmp_path) -> None:
    """После ротации старый ключ всё ещё расшифровывает старые сообщения."""
    keyring = tmp_path / "keyring.json"
    settings = Settings(
        _env_file=None,
        encryption_key=None,
        key_id="key-1",
        keyring_file=keyring,
        log_dir=tmp_path / "logs",
    )
    manager = KeyManager(settings)
    old_key_id = manager.current_key_id
    sealed = CryptoService(manager).encrypt(PLAINTEXT)

    manager.rotate("key-2")
    service = CryptoService(manager)

    assert (
        service.decrypt(
            sealed.nonce,
            sealed.ciphertext,
            sealed.tag,
            key_id=old_key_id,
        )
        == PLAINTEXT
    )


def test_sealed_payload_repr_hides_bulk_data() -> None:
    service = CryptoService(KeyManager.from_key(os.urandom(KEY_SIZE)))
    sealed = service.encrypt(PLAINTEXT)
    text = repr(sealed)

    assert "ciphertext=" in text
    assert sealed.ciphertext.hex() not in text
