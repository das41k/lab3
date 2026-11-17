"""Защищённый протокол: запечатывание и распаковка конвертов.

``BankingProtocol`` связывает структуры данных протокола и
криптографический слой, но не знает ничего о сети и бизнес-логике
(принцип разделения ответственности из ЛР3).
"""

from __future__ import annotations

from crypto.crypto_service import CryptoService, SealedPayload
from protocol.codec import DEFAULT_MAX_MESSAGE_BYTES
from protocol.messages import (
    PROTOCOL_VERSION,
    EncryptedMessage,
    MessageFormatError,
    MessageKind,
    MessageTooLargeError,
    ProtocolMessage,
    Request,
    Response,
    UnsupportedVersionError,
    build_aad,
)


class BankingProtocol:
    """Формирует/проверяет защищённые сообщения протокола."""

    def __init__(
        self,
        crypto: CryptoService,
        *,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> None:
        if max_message_bytes <= 0:
            raise ValueError("max_message_bytes must be positive")
        self._crypto = crypto
        self._max_message_bytes = max_message_bytes

    @property
    def crypto(self) -> CryptoService:
        return self._crypto

    @property
    def max_message_bytes(self) -> int:
        return self._max_message_bytes

    # ── Запечатывание ────────────────────────────────────────────────────

    def seal(
        self,
        message: Request | Response,
        *,
        key_id: str | None = None,
    ) -> EncryptedMessage:
        """Шифрует открытое сообщение и возвращает конверт."""
        if not isinstance(message, (Request, Response)):
            raise TypeError(
                f"cannot seal message of type {type(message)!r}"
            )

        resolved_key_id = key_id or self._crypto.current_key_id
        aad = build_aad(
            message.version,
            message.request_id,
            message.kind,
            resolved_key_id,
        )
        sealed: SealedPayload = self._crypto.encrypt(
            message.to_json().encode("utf-8"),
            aad=aad,
            key_id=resolved_key_id,
        )
        return EncryptedMessage(
            version=message.version,
            request_id=message.request_id,
            kind=message.kind,
            key_id=resolved_key_id,
            nonce=sealed.nonce,
            ciphertext=sealed.ciphertext,
            tag=sealed.tag,
        )

    def seal_bytes(
        self,
        message: Request | Response,
        *,
        key_id: str | None = None,
    ) -> bytes:
        """Шифрует сообщение и сразу кодирует в сетевой кадр."""
        return self.encode(self.seal(message, key_id=key_id))

    # ── Распаковка ───────────────────────────────────────────────────────

    def open(self, envelope: EncryptedMessage) -> Request | Response:
        """Проверяет tag/AAD и возвращает типизированное сообщение."""
        if not isinstance(envelope, EncryptedMessage):
            raise TypeError(
                f"expected EncryptedMessage, got {type(envelope)!r}"
            )

        plaintext = self._crypto.decrypt(
            envelope.nonce,
            envelope.ciphertext,
            envelope.tag,
            aad=envelope.aad,
            key_id=envelope.key_id,
        )
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise MessageFormatError(
                "decrypted payload is not valid UTF-8"
            ) from exc

        message_class = (
            Request if envelope.kind is MessageKind.REQUEST else Response
        )
        message: ProtocolMessage = message_class.from_json(text)

        if message.request_id != envelope.request_id:
            raise MessageFormatError("request_id mismatch")
        if message.version != envelope.version:
            raise MessageFormatError("version mismatch")
        if message.version != PROTOCOL_VERSION:
            raise UnsupportedVersionError(message.version)
        return message  # type: ignore[return-value]

    def open_bytes(self, raw: bytes | str) -> Request | Response:
        """Разбирает сетевой кадр, проверяет tag и возвращает сообщение."""
        return self.open(self.decode(raw))

    # ── Сетевой формат ───────────────────────────────────────────────────

    def encode(self, envelope: EncryptedMessage) -> bytes:
        """Кодирует конверт в кадр 'JSON\\n' с контролем размера."""
        frame = envelope.to_json().encode("utf-8") + b"\n"
        if len(frame) > self._max_message_bytes:
            raise MessageTooLargeError(
                len(frame), self._max_message_bytes
            )
        return frame

    def decode(self, raw: bytes | str) -> EncryptedMessage:
        """Разбирает кадр (без '\\n') в :class:`EncryptedMessage`."""
        if isinstance(raw, bytes):
            if len(raw) > self._max_message_bytes:
                raise MessageTooLargeError(
                    len(raw), self._max_message_bytes
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise MessageFormatError(
                    "envelope is not valid UTF-8"
                ) from exc
        else:
            text = raw

        envelope = EncryptedMessage.from_json(text.strip())
        if not isinstance(envelope, EncryptedMessage):
            raise MessageFormatError("envelope must be an encrypted message")
        return envelope
