"""Тесты формата сообщений и защищённого конверта."""

from __future__ import annotations

import os
import socket

import pytest

from crypto.crypto_service import CryptoService
from crypto.errors import AuthenticationError, UnknownKeyError
from protocol.codec import MessageFramer
from protocol.messages import (
    PROTOCOL_VERSION,
    EncryptedMessage,
    ErrorCode,
    MessageTooLargeError,
    MessageType,
    Request,
    Response,
    UnsupportedVersionError,
)
from protocol.secure import BankingProtocol


def make_transfer() -> Request:
    return Request(
        type=MessageType.TRANSFER,
        payload={
            "from": "ACC-1001",
            "to": "ACC-1002",
            "amount": 500.0,
        },
    )


def test_request_is_a_data_structure() -> None:
    request = Request(
        type=MessageType.HELLO, payload={"x": 1}
    )
    assert request.kind.value == "REQUEST"
    assert request.version == PROTOCOL_VERSION
    assert request["type"] == MessageType.HELLO
    assert request.to_dict()["payload"] == {"x": 1}
    assert Request.from_json(request.to_json()) == request


def test_response_is_a_data_structure() -> None:
    response = Response.success("req-1", {"balance": 10.0})
    assert response.is_success
    assert response["status"] == "SUCCESS"
    assert response["payload"]["balance"] == 10.0
    assert Response.from_json(response.to_json()) == response

    failure = Response.failure(
        "req-2", ErrorCode.INVALID_DATA, "bad amount"
    )
    assert not failure.is_success
    assert failure.error is not None
    assert failure.error.code is ErrorCode.INVALID_DATA


def test_request_roundtrip_through_envelope(protocol: BankingProtocol) -> None:
    request = make_transfer()
    envelope = protocol.seal(request)

    wire = protocol.encode(envelope)
    restored_envelope = protocol.decode(wire)
    restored = protocol.open(restored_envelope)

    assert isinstance(restored, Request)
    assert restored == request
    assert restored_envelope == envelope


def test_response_roundtrip_through_envelope(
    protocol: BankingProtocol,
) -> None:
    response = Response.success("req-42", {"balance": 9500.0})
    envelope = protocol.seal(response)
    restored = protocol.open(protocol.decode(protocol.encode(envelope)))

    assert isinstance(restored, Response)
    assert restored == response


def test_envelope_json_roundtrip(protocol: BankingProtocol) -> None:
    envelope = protocol.seal(make_transfer())
    restored = EncryptedMessage.from_json(envelope.to_json())

    assert restored == envelope
    assert restored.nonce == envelope.nonce
    assert restored.aad == envelope.aad


def test_plaintext_is_not_visible_on_wire(
    protocol: BankingProtocol,
) -> None:
    wire = protocol.encode(protocol.seal(make_transfer()))

    for marker in (
        b"ACC-1001",
        b"ACC-1002",
        b"500.0",
        b"TRANSFER",
        b"payload",
    ):
        assert marker not in wire

    # Открытыми остаются только метаданные конверта.
    assert b"key_id" in wire
    assert b"nonce" in wire
    assert b"ciphertext" in wire
    assert b"tag" in wire


def test_envelope_binds_request_id_via_aad(
    protocol: BankingProtocol,
) -> None:
    envelope = protocol.seal(make_transfer())
    data = envelope.to_dict()
    data["request_id"] = "attacker-controlled"
    tampered = EncryptedMessage.from_dict(data)

    with pytest.raises(AuthenticationError):
        protocol.open(tampered)


def test_envelope_binds_key_id_via_aad(
    protocol: BankingProtocol,
) -> None:
    envelope = protocol.seal(make_transfer())
    data = envelope.to_dict()
    data["key_id"] = "key-other"
    tampered = EncryptedMessage.from_dict(data)

    with pytest.raises((AuthenticationError, UnknownKeyError)):
        protocol.open(tampered)


def test_envelope_binds_kind_via_aad(protocol: BankingProtocol) -> None:
    envelope = protocol.seal(make_transfer())
    data = envelope.to_dict()
    data["kind"] = "RESPONSE"
    tampered = EncryptedMessage.from_dict(data)

    with pytest.raises(AuthenticationError):
        protocol.open(tampered)


def test_tampered_ciphertext_is_rejected(
    protocol: BankingProtocol,
) -> None:
    envelope = protocol.seal(make_transfer())
    damaged = bytearray(envelope.ciphertext)
    damaged[0] ^= 0xFF
    tampered = EncryptedMessage(
        version=envelope.version,
        request_id=envelope.request_id,
        kind=envelope.kind,
        key_id=envelope.key_id,
        nonce=envelope.nonce,
        ciphertext=bytes(damaged),
        tag=envelope.tag,
    )

    with pytest.raises(AuthenticationError):
        protocol.open(tampered)


def test_unsupported_version_is_rejected(
    protocol: BankingProtocol,
) -> None:
    envelope = protocol.seal(
        Request(type=MessageType.HELLO, version="99.0")
    )

    with pytest.raises(UnsupportedVersionError):
        protocol.open(envelope)


def test_unknown_key_id_is_rejected(
    crypto: CryptoService,
) -> None:
    protocol = BankingProtocol(crypto)
    envelope = protocol.seal(make_transfer())

    # Подменяем key_id и пересобираем AAD-конверт без изменения ciphertext.
    tampered = EncryptedMessage(
        version=envelope.version,
        request_id=envelope.request_id,
        kind=envelope.kind,
        key_id="missing-key",
        nonce=os.urandom(12),
        ciphertext=envelope.ciphertext,
        tag=envelope.tag,
    )

    with pytest.raises(UnknownKeyError):
        protocol.open(tampered)


def test_message_size_limit() -> None:
    from crypto.key_manager import KeyManager

    service = CryptoService(KeyManager.from_key(os.urandom(32)))
    protocol = BankingProtocol(service, max_message_bytes=128)
    envelope = protocol.seal(Request(type=MessageType.HELLO))

    with pytest.raises(MessageTooLargeError):
        protocol.encode(envelope)


def test_framer_roundtrip() -> None:
    left, right = socket.socketpair()
    try:
        sender = MessageFramer(left, max_message_bytes=1024)
        receiver = MessageFramer(right, max_message_bytes=1024)
        sender.send(b'{"hello":1}')
        sender.send(b"second")
        assert receiver.recv() == b'{"hello":1}'
        assert receiver.recv() == b"second"
    finally:
        left.close()
        right.close()


def test_framer_rejects_oversized_frame() -> None:
    left, right = socket.socketpair()
    try:
        framer = MessageFramer(left, max_message_bytes=32)
        with pytest.raises(MessageTooLargeError):
            framer.send(b"x" * 64)
    finally:
        left.close()
        right.close()


def test_framer_receives_partial_then_complete() -> None:
    left, right = socket.socketpair()
    try:
        receiver = MessageFramer(left, max_message_bytes=1024)
        right.sendall(b'{"a":')
        right.sendall(b'1}\n')
        assert receiver.recv() == b'{"a":1}'
    finally:
        left.close()
        right.close()
