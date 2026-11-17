"""Общие фикстуры тестов."""

from __future__ import annotations

import base64

import pytest

from config import Settings
from crypto.crypto_service import CryptoService
from crypto.key_manager import KeyManager
from protocol.secure import BankingProtocol

TEST_KEY = bytes(range(32))
TEST_KEY_B64 = base64.b64encode(TEST_KEY).decode("ascii")


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        _env_file=None,
        host="127.0.0.1",
        port=0,
        encryption_key=TEST_KEY_B64,
        key_id="key-test",
        keyring_file=tmp_path / "keys" / "keyring.json",
        log_dir=tmp_path / "logs",
        max_message_bytes=64 * 1024,
        timeout_seconds=2.0,
        max_retries=2,
        strict_nonce_check=True,
        slow_test_seconds=1.0,
    )


@pytest.fixture
def key_manager(settings: Settings) -> KeyManager:
    return KeyManager(settings)


@pytest.fixture
def crypto(key_manager: KeyManager) -> CryptoService:
    return CryptoService(key_manager)


@pytest.fixture
def protocol(crypto: CryptoService) -> BankingProtocol:
    return BankingProtocol(crypto, max_message_bytes=64 * 1024)


@pytest.fixture
def server(settings: Settings):
    from server.server import BankingServer

    instance = BankingServer(settings)
    instance.service.reset()
    port = instance.start_background()
    try:
        yield instance, port
    finally:
        instance.stop()
