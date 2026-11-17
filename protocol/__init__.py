"""Публичный API протокола Banking Protocol v1.0 (защищённый обмен)."""

from protocol.codec import DEFAULT_MAX_MESSAGE_BYTES, MessageFramer
from protocol.messages import (
    PROTOCOL_VERSION,
    EncryptedMessage,
    ErrorCode,
    ErrorInfo,
    MessageFormatError,
    MessageKind,
    MessageTooLargeError,
    MessageType,
    ProtocolError,
    ProtocolMessage,
    Request,
    Response,
    UnsupportedVersionError,
    build_aad,
)
from protocol.secure import BankingProtocol

__all__ = [
    "PROTOCOL_VERSION",
    "MessageType",
    "MessageKind",
    "ErrorCode",
    "ErrorInfo",
    "ProtocolMessage",
    "Request",
    "Response",
    "EncryptedMessage",
    "ProtocolError",
    "MessageFormatError",
    "MessageTooLargeError",
    "UnsupportedVersionError",
    "build_aad",
    "BankingProtocol",
    "MessageFramer",
    "DEFAULT_MAX_MESSAGE_BYTES",
]
