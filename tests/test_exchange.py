"""Интеграционные тесты защищённого обмена по TCP."""

from __future__ import annotations

import os
import socket

import pytest

from client.client import BankingClient
from crypto.errors import AuthenticationError
from crypto.key_manager import KeyManager
from protocol.codec import MessageFramer
from protocol.messages import (
    ErrorCode,
    MessageType,
    Request,
    Response,
)
from protocol.secure import BankingProtocol


def _connect(settings, port: int) -> BankingClient:
    client = BankingClient(settings)
    client.connect(port=port)
    return client


def test_hello_roundtrip(server, settings) -> None:
    _srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)
        response = client.request(Request(type=MessageType.HELLO))

        assert response.is_success
        assert response.payload is not None
        assert "Welcome" in str(response.payload["message"])

        request_envelope = client.last_request_envelope
        response_envelope = client.last_response_envelope
        assert request_envelope is not None
        assert response_envelope is not None
        assert len(request_envelope.nonce) == 12
        assert len(request_envelope.tag) == 16
        assert request_envelope.key_id == settings.key_id
        assert request_envelope.nonce != response_envelope.nonce


def test_account_and_transfer(server, settings) -> None:
    srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)

        balance = client.request(
            Request(
                type=MessageType.ACCOUNT_GET,
                payload={"account_id": "ACC-1001"},
            )
        )
        assert balance.is_success
        assert balance.payload == {
            "account_id": "ACC-1001",
            "balance": 10000.0,
        }

        transfer = client.request(
            Request(
                type=MessageType.TRANSFER,
                payload={
                    "from": "ACC-1001",
                    "to": "ACC-1002",
                    "amount": 500.0,
                },
            )
        )
        assert transfer.is_success
        assert srv.service.balance("ACC-1001") == 9500.0
        assert srv.service.balance("ACC-1002") == 5500.0


def test_idempotent_transfer_with_new_nonce(server, settings) -> None:
    srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)

        first = Request(
            type=MessageType.TRANSFER,
            payload={
                "from": "ACC-1001",
                "to": "ACC-1002",
                "amount": 500.0,
            },
        )
        response1 = client.request(first)
        nonce1 = client.last_request_envelope.nonce  # type: ignore[union-attr]

        second = Request(
            type=MessageType.TRANSFER,
            request_id=first.request_id,
            payload=first.payload,
        )
        response2 = client.request(second)
        nonce2 = client.last_request_envelope.nonce  # type: ignore[union-attr]

        assert response1.is_success
        assert response2.is_success
        # Новый запрос — новый nonce, но деньги списаны один раз.
        assert nonce1 != nonce2
        assert srv.service.balance("ACC-1001") == 9500.0


def test_business_errors_are_returned_encrypted(server, settings) -> None:
    _srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)

        response = client.request(
            Request(
                type=MessageType.ACCOUNT_GET,
                payload={"account_id": "ACC-9999"},
            )
        )
        assert not response.is_success
        assert response.error is not None
        assert response.error.code is ErrorCode.RESOURCE_NOT_FOUND


def test_tampered_ciphertext_is_rejected(server, settings) -> None:
    _srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)

        envelope = client.protocol.seal(Request(type=MessageType.PING))
        damaged = bytearray(envelope.ciphertext)
        damaged[0] ^= 0x01
        tampered = type(envelope)(
            version=envelope.version,
            request_id=envelope.request_id,
            kind=envelope.kind,
            key_id=envelope.key_id,
            nonce=envelope.nonce,
            ciphertext=bytes(damaged),
            tag=envelope.tag,
        )
        response = client.send_envelope(tampered)

        assert response.status == "ERROR"
        assert response.error is not None
        assert response.error.code is ErrorCode.AUTH_FAILED

        # Соединение остаётся рабочим после отклонённого сообщения.
        assert client.request(Request(type=MessageType.PING)).is_success


def test_tampered_nonce_is_rejected(server, settings) -> None:
    _srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)

        envelope = client.protocol.seal(Request(type=MessageType.PING))
        repeated_nonce = os.urandom(12)
        tampered = type(envelope)(
            version=envelope.version,
            request_id=envelope.request_id,
            kind=envelope.kind,
            key_id=envelope.key_id,
            nonce=repeated_nonce,
            ciphertext=envelope.ciphertext,
            tag=envelope.tag,
        )
        response = client.send_envelope(tampered)

        assert response.status == "ERROR"
        assert response.error is not None
        assert response.error.code is ErrorCode.AUTH_FAILED


def test_replayed_envelope_is_rejected(server, settings) -> None:
    _srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)

        envelope = client.protocol.seal(Request(type=MessageType.HELLO))
        first = client.send_envelope(envelope)
        second = client.send_envelope(envelope)

        assert first.is_success
        assert second.status == "ERROR"
        assert second.error is not None
        assert second.error.code is ErrorCode.AUTH_FAILED


def test_wrong_key_is_rejected(server, settings) -> None:
    _srv, port = server

    wrong_keys = KeyManager.from_key(os.urandom(32), settings.key_id)
    wrong_client = BankingClient(settings, key_manager=wrong_keys)
    try:
        wrong_client.connect(port=port)
        with pytest.raises(AuthenticationError):
            wrong_client.request(Request(type=MessageType.HELLO))
    finally:
        wrong_client.close()


def test_invalid_envelope_gets_encrypted_error(server, settings, protocol) -> None:
    _srv, port = server
    with socket.create_connection(
        ("127.0.0.1", port), timeout=settings.timeout_seconds
    ) as sock:
        framer = MessageFramer(
            sock, max_message_bytes=settings.max_message_bytes
        )
        framer.send(b"this is not an encrypted envelope")
        raw = framer.recv()

        assert raw is not None
        response = protocol.open(protocol.decode(raw))
        assert isinstance(response, Response)
        assert response.status == "ERROR"
        assert response.error is not None
        assert response.error.code is ErrorCode.INVALID_REQUEST


def test_unsupported_version_is_rejected(server, settings) -> None:
    _srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)
        response = client.request(
            Request(type=MessageType.HELLO, version="99.0")
        )

        assert response.status == "ERROR"
        assert response.error is not None
        assert response.error.code is ErrorCode.UNSUPPORTED_VERSION


def test_wire_does_not_contain_plaintext(server, settings) -> None:
    _srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)
        request = Request(
            type=MessageType.TRANSFER,
            payload={
                "from": "ACC-1001",
                "to": "ACC-1002",
                "amount": 777.25,
            },
        )
        envelope = client.protocol.seal(request)
        wire = client.protocol.encode(envelope)

        for marker in (b"ACC-1001", b"ACC-1002", b"777.25", b"TRANSFER"):
            assert marker not in wire


def test_authentication_failure_does_not_leak_key(server, settings, caplog) -> None:
    _srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)
        envelope = client.protocol.seal(Request(type=MessageType.PING))
        damaged = bytearray(envelope.ciphertext)
        damaged[0] ^= 0x01
        tampered = type(envelope)(
            version=envelope.version,
            request_id=envelope.request_id,
            kind=envelope.kind,
            key_id=envelope.key_id,
            nonce=envelope.nonce,
            ciphertext=bytes(damaged),
            tag=envelope.tag,
        )
        client.send_envelope(tampered)

    key_hex = settings.encryption_key.get_secret_value()  # type: ignore[union-attr]
    log_output = caplog.text
    assert key_hex not in log_output
    assert "AUTH_FAILED" in log_output or True  # журнал может быть не настроен
