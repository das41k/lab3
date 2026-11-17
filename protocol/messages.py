"""Структуры данных протокола Banking Protocol v1.0 (ЛР3).

Протокол больше не «собирается» набором функций: каждое сообщение — это
отдельный неизменяемый класс данных:

* :class:`Request`          — запрос клиента;
* :class:`Response`         — ответ сервера;
* :class:`EncryptedMessage` — защищённый конверт (nonce + ciphertext + tag);
* :class:`ProtocolMessage`  — общий базовый класс с сериализацией.

Внешний (сетевой) формат: одна JSON-строка на сообщение, разделитель — '\\n'.
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from crypto.constants import NONCE_SIZE, TAG_SIZE

PROTOCOL_VERSION = "1.0"


# ─────────────────────────────────────────────────────────────────────────────
# Перечисления протокола
# ─────────────────────────────────────────────────────────────────────────────

class MessageType(str, Enum):
    HELLO       = "HELLO"
    ACCOUNT_GET = "ACCOUNT_GET"
    TRANSFER    = "TRANSFER"
    PING        = "PING"
    PONG        = "PONG"
    ERROR       = "ERROR"
    SLOW_TEST   = "SLOW_TEST"

    def __str__(self) -> str:
        return self.value


class ErrorCode(str, Enum):
    INVALID_REQUEST     = "INVALID_REQUEST"
    INVALID_DATA        = "INVALID_DATA"
    RESOURCE_NOT_FOUND  = "RESOURCE_NOT_FOUND"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    INTERNAL_ERROR      = "INTERNAL_ERROR"
    AUTH_FAILED         = "AUTH_FAILED"
    MESSAGE_TOO_LARGE   = "MESSAGE_TOO_LARGE"

    def __str__(self) -> str:
        return self.value


class MessageKind(str, Enum):
    """Направление сообщения внутри зашифрованного конверта."""

    REQUEST  = "REQUEST"
    RESPONSE = "RESPONSE"

    def __str__(self) -> str:
        return self.value


# ─────────────────────────────────────────────────────────────────────────────
# Исключения
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolError(Exception):
    """Ошибка протокола с машинным кодом."""

    def __init__(self, code: ErrorCode | str, message: str):
        self.code = code if isinstance(code, ErrorCode) else ErrorCode(code)
        self.message = message
        super().__init__(message)


class MessageFormatError(ProtocolError):
    """Сообщение не соответствует формату протокола."""

    def __init__(self, message: str):
        super().__init__(ErrorCode.INVALID_REQUEST, message)


class UnsupportedVersionError(ProtocolError):
    """Версия протокола не поддерживается."""

    def __init__(self, version: str):
        self.version = version
        super().__init__(
            ErrorCode.UNSUPPORTED_VERSION,
            f"unsupported protocol version: {version!r}",
        )


class MessageTooLargeError(ProtocolError):
    """Сообщение превышает допустимый размер."""

    def __init__(self, size: int, limit: int):
        self.size = size
        self.limit = limit
        super().__init__(
            ErrorCode.MESSAGE_TOO_LARGE,
            f"message of {size} bytes exceeds limit of {limit} bytes",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Вспомогательные функции
# ─────────────────────────────────────────────────────────────────────────────

def _new_request_id() -> str:
    return str(uuid.uuid4())


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    if isinstance(value, set):
        return frozenset(_freeze(v) for v in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _thaw(v) for k, v in value.items()}
    if isinstance(value, tuple):
        return [_thaw(v) for v in value]
    if isinstance(value, frozenset):
        return [_thaw(v) for v in value]
    return value


def _require(data: Mapping[str, Any], key: str) -> Any:
    if key not in data:
        raise MessageFormatError(f"missing required field: {key!r}")
    return data[key]


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise MessageFormatError(f"field {field_name!r} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MessageFormatError(
            f"field {field_name!r} is not valid base64"
        ) from exc


def build_aad(
    version: str,
    request_id: str,
    kind: MessageKind,
    key_id: str,
) -> bytes:
    """Формирует AAD (Additional Authenticated Data) для конверта.

    AAD не шифруется, но его целостность защищается authentication tag.
    Длина каждого поля кодируется явно, чтобы избежать неоднозначности
    при склейке строк.
    """
    def part(value: str) -> bytes:
        raw = value.encode("utf-8")
        return len(raw).to_bytes(4, "big") + raw

    return (
        b"BSP1"
        + part(version)
        + part(kind.value)
        + part(request_id)
        + part(key_id)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Базовый класс сообщения
# ─────────────────────────────────────────────────────────────────────────────

class ProtocolMessage(ABC):
    """Общий интерфейс сообщения протокола."""

    version: str
    request_id: str
    kind: MessageKind

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Возвращает представление сообщения в виде словаря."""

    def to_json(self) -> str:
        """Компактная JSON-строка (UTF-8-совместимая)."""
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProtocolMessage":
        raise NotImplementedError

    @classmethod
    def from_json(cls, raw: str | bytes) -> "ProtocolMessage":
        """Разбирает JSON; ошибки приводятся к :class:`MessageFormatError`."""
        if isinstance(raw, bytes):
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise MessageFormatError(
                    "message is not valid UTF-8"
                ) from exc
        else:
            text = raw

        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise MessageFormatError(f"invalid JSON: {exc.msg}") from exc

        if not isinstance(data, dict):
            raise MessageFormatError("message must be a JSON object")
        return cls.from_dict(data)

    # Удобная совместимость со словарным доступом: req["request_id"].
    def __getitem__(self, key: str) -> Any:
        try:
            return self.to_dict()[key]
        except KeyError:
            raise KeyError(key) from None

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)

    def __contains__(self, key: object) -> bool:
        return key in self.to_dict()


# ─────────────────────────────────────────────────────────────────────────────
# Ошибка внутри ответа
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, kw_only=True)
class ErrorInfo:
    code: ErrorCode
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.code, ErrorCode):
            try:
                object.__setattr__(self, "code", ErrorCode(self.code))
            except ValueError as exc:
                raise MessageFormatError(
                    f"unknown error code: {self.code!r}"
                ) from exc

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "message": self.message}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ErrorInfo":
        return cls(
            code=_require(data, "code"),
            message=str(data.get("message", "")),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Запрос клиента → сервер
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, kw_only=True)
class Request(ProtocolMessage):
    """Открытый (расшифрованный) запрос клиента."""

    type: MessageType
    payload: Mapping[str, Any] = field(default_factory=dict)
    version: str = PROTOCOL_VERSION
    request_id: str = field(default_factory=_new_request_id)
    timestamp: str = field(default_factory=_utc_now_iso)
    kind: MessageKind = field(default=MessageKind.REQUEST, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.type, MessageType):
            object.__setattr__(self, "type", MessageType(self.type))
        object.__setattr__(self, "payload", _freeze(self.payload or {}))
        if not isinstance(self.request_id, str) or not self.request_id:
            raise MessageFormatError("request_id must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "version":    self.version,
            "request_id": self.request_id,
            "timestamp":  self.timestamp,
            "type":       self.type.value,
            "payload":    _thaw(self.payload),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Request":
        raw_type = _require(data, "type")
        try:
            message_type = MessageType(raw_type)
        except ValueError as exc:
            raise MessageFormatError(
                f"unknown message type: {raw_type!r}"
            ) from exc

        payload = data.get("payload", {})
        if not isinstance(payload, Mapping):
            raise MessageFormatError("payload must be a JSON object")

        return cls(
            version=str(data.get("version", PROTOCOL_VERSION)),
            request_id=str(_require(data, "request_id")),
            timestamp=str(data.get("timestamp", _utc_now_iso())),
            type=message_type,
            payload=payload,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Ответ сервер → клиент
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, kw_only=True)
class Response(ProtocolMessage):
    """Открытый (расшифрованный) ответ сервера."""

    request_id: str
    status: str = "SUCCESS"
    payload: Mapping[str, Any] | None = None
    error: ErrorInfo | None = None
    version: str = PROTOCOL_VERSION
    kind: MessageKind = field(default=MessageKind.RESPONSE, init=False)

    def __post_init__(self) -> None:
        if self.payload is not None:
            object.__setattr__(self, "payload", _freeze(self.payload))
        if self.error is not None and not isinstance(self.error, ErrorInfo):
            object.__setattr__(
                self, "error", ErrorInfo.from_dict(self.error)
            )

    @property
    def is_success(self) -> bool:
        return self.status == "SUCCESS"

    @classmethod
    def success(
        cls,
        request_id: str,
        payload: Mapping[str, Any] | None = None,
    ) -> "Response":
        return cls(request_id=request_id, status="SUCCESS", payload=payload)

    @classmethod
    def failure(
        cls,
        request_id: str,
        code: ErrorCode | str,
        message: str,
    ) -> "Response":
        return cls(
            request_id=request_id,
            status="ERROR",
            error=ErrorInfo(code=ErrorCode(code), message=message),
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "version":    self.version,
            "request_id": self.request_id,
            "status":     self.status,
        }
        if self.payload is not None:
            data["payload"] = _thaw(self.payload)
        if self.error is not None:
            data["error"] = self.error.to_dict()
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Response":
        raw_error = data.get("error")
        error = None
        if raw_error is not None:
            if not isinstance(raw_error, Mapping):
                raise MessageFormatError("error must be a JSON object")
            error = ErrorInfo.from_dict(raw_error)

        payload = data.get("payload")
        if payload is not None and not isinstance(payload, Mapping):
            raise MessageFormatError("payload must be a JSON object")

        return cls(
            version=str(data.get("version", PROTOCOL_VERSION)),
            request_id=str(_require(data, "request_id")),
            status=str(data.get("status", "SUCCESS")),
            payload=payload,
            error=error,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Защищённый конверт
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True, kw_only=True)
class EncryptedMessage(ProtocolMessage):
    """Зашифрованный конверт, передаваемый по TCP.

    Поля ``version``, ``request_id``, ``kind`` и ``key_id`` остаются
    открытыми, но аутентифицируются через AAD. ``nonce`` не является
    секретом и передаётся вместе с ciphertext/tag.
    """

    key_id: str
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    kind: MessageKind = MessageKind.REQUEST
    version: str = PROTOCOL_VERSION
    request_id: str = field(default_factory=_new_request_id)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, MessageKind):
            object.__setattr__(self, "kind", MessageKind(self.kind))
        for name in ("nonce", "ciphertext", "tag"):
            value = getattr(self, name)
            if not isinstance(value, (bytes, bytearray)):
                raise MessageFormatError(f"{name} must be bytes")
            object.__setattr__(self, name, bytes(value))

        if len(self.nonce) != NONCE_SIZE:
            raise MessageFormatError(
                f"nonce must be {NONCE_SIZE} bytes, got {len(self.nonce)}"
            )
        if len(self.tag) != TAG_SIZE:
            raise MessageFormatError(
                f"tag must be {TAG_SIZE} bytes, got {len(self.tag)}"
            )
        if not self.key_id:
            raise MessageFormatError("key_id must be a non-empty string")

    @property
    def aad(self) -> bytes:
        """AAD, вычисляемый из открытых (аутентифицируемых) полей."""
        return build_aad(
            self.version, self.request_id, self.kind, self.key_id
        )

    @property
    def wire_size(self) -> int:
        """Размер конверта в JSON (без разделителя '\\n')."""
        return len(self.to_json().encode("utf-8"))

    def to_dict(self) -> dict[str, str]:
        return {
            "version":    self.version,
            "request_id": self.request_id,
            "kind":       self.kind.value,
            "key_id":     self.key_id,
            "nonce":      _b64encode(self.nonce),
            "ciphertext": _b64encode(self.ciphertext),
            "tag":        _b64encode(self.tag),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EncryptedMessage":
        raw_kind = data.get("kind", MessageKind.REQUEST.value)
        try:
            kind = MessageKind(raw_kind)
        except ValueError as exc:
            raise MessageFormatError(
                f"unknown message kind: {raw_kind!r}"
            ) from exc

        return cls(
            version=str(data.get("version", PROTOCOL_VERSION)),
            request_id=str(_require(data, "request_id")),
            kind=kind,
            key_id=str(_require(data, "key_id")),
            nonce=_b64decode(_require(data, "nonce"), "nonce"),
            ciphertext=_b64decode(
                _require(data, "ciphertext"), "ciphertext"
            ),
            tag=_b64decode(_require(data, "tag"), "tag"),
        )
