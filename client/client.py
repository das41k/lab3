"""TCP-клиент Banking Protocol с AES-GCM-защитой (ЛР3).

Каждый запрос запечатывается новым nonce. Ответ сервера расшифровывается
и проверяется по authentication tag; при несовпадении ключа или изменении
данных выбрасывается :class:`AuthenticationError`.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import Settings, get_settings
from crypto.crypto_service import CryptoService
from crypto.errors import CryptoError
from crypto.key_manager import KeyManager
from logging_setup import setup_logging
from protocol.codec import MessageFramer
from protocol.messages import (
    EncryptedMessage,
    ErrorCode,
    MessageType,
    ProtocolError,
    Request,
    Response,
)
from protocol.secure import BankingProtocol

# Имя логгера задаётся явно: при запуске ``python -m client.client``
# модуль выполняется как ``__main__``, и ``__name__`` не совпал бы с именем,
# которое настраивает setup_logging().
LOGGER_NAME = "client.client"

logger = logging.getLogger(LOGGER_NAME)


def _nonce_tag(nonce: bytes) -> str:
    import hashlib

    return hashlib.sha256(nonce).hexdigest()[:8]


def _request_loop(
    sock: socket.socket,
    framer: MessageFramer,
    protocol: BankingProtocol,
    request: Request,
    *,
    max_retries: int,
    timeout: float,
) -> tuple[Response, EncryptedMessage, EncryptedMessage]:
    """Выполняет запрос с ретраями по таймауту.

    Каждая попытка шифруется заново — с новым nonce (требование ЛР3).
    """
    request_id = request.request_id
    message_type = request.type
    last_request_envelope: EncryptedMessage | None = None
    last_response_envelope: EncryptedMessage | None = None

    for attempt in range(1, max_retries + 1):
        try:
            envelope = protocol.seal(request)
            last_request_envelope = envelope
            logger.info(
                "request_id=%s type=%s status=SENDING attempt=%s "
                "key_id=%s nonce=%s",
                request_id,
                message_type,
                attempt,
                envelope.key_id,
                _nonce_tag(envelope.nonce),
            )

            sock.settimeout(timeout)
            framer.send(protocol.encode(envelope))

            raw = framer.recv()
            if raw is None:
                raise ConnectionError("Server closed connection")

            response_envelope = protocol.decode(raw)
            last_response_envelope = response_envelope
            message = protocol.open(response_envelope)
            if not isinstance(message, Response):
                raise ProtocolError(
                    ErrorCode.INVALID_REQUEST,
                    "Expected response, got request",
                )

            if message.request_id not in (request_id, "UNKNOWN"):
                logger.warning(
                    "request_id=%s type=%s status=REQUEST_ID_MISMATCH "
                    "response_request_id=%s",
                    request_id,
                    message_type,
                    message.request_id,
                )

            logger.info(
                "request_id=%s type=%s status=RECEIVED attempt=%s "
                "key_id=%s nonce=%s",
                request_id,
                message_type,
                attempt,
                response_envelope.key_id,
                _nonce_tag(response_envelope.nonce),
            )
            return message, envelope, response_envelope

        except socket.timeout:
            logger.warning(
                "request_id=%s type=%s status=TIMEOUT attempt=%s/%s",
                request_id,
                message_type,
                attempt,
                max_retries,
            )
            if attempt == max_retries:
                logger.error(
                    "request_id=%s type=%s status=ALL_RETRIES_FAILED",
                    request_id,
                    message_type,
                )
                raise TimeoutError(
                    f"Timeout after {max_retries} attempts"
                ) from None
            logger.info(
                "request_id=%s type=%s status=RETRYING",
                request_id,
                message_type,
            )
        except CryptoError as exc:
            logger.error(
                "request_id=%s type=%s status=AUTH_FAILED reason=%s",
                request_id,
                message_type,
                type(exc).__name__,
            )
            raise

    # Логически недостижимо: цикл либо вернул ответ, либо выбросил TimeoutError.
    raise TimeoutError(f"Timeout after {max_retries} attempts")


def send_request(
    sock: socket.socket,
    request: Request,
    protocol: BankingProtocol,
    *,
    max_retries: int = 3,
    timeout: float = 5.0,
    framer: MessageFramer | None = None,
) -> Response:
    """Отправляет один :class:`Request` и возвращает :class:`Response`."""
    if framer is None:
        framer = MessageFramer(
            sock, max_message_bytes=protocol.max_message_bytes
        )
    response, _, _ = _request_loop(
        sock,
        framer,
        protocol,
        request,
        max_retries=max_retries,
        timeout=timeout,
    )
    return response


class BankingClient:
    """Удобная обёртка над сокетом и защищённым протоколом."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        key_manager: KeyManager | None = None,
        protocol: BankingProtocol | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.keys = key_manager or KeyManager(self.settings)
        self.crypto = CryptoService(
            self.keys,
            strict_nonce_check=self.settings.strict_nonce_check,
        )
        self.protocol = protocol or BankingProtocol(
            self.crypto,
            max_message_bytes=self.settings.max_message_bytes,
        )
        self._sock: socket.socket | None = None
        self._framer: MessageFramer | None = None
        self._host: str | None = None
        self._port: int | None = None
        self._lock = threading.RLock()

        self.last_request_envelope: EncryptedMessage | None = None
        self.last_response_envelope: EncryptedMessage | None = None

    # ── Подключение ──────────────────────────────────────────────────────

    def connect(
        self,
        host: str | None = None,
        port: int | None = None,
        *,
        timeout: float | None = None,
    ) -> None:
        with self._lock:
            self.close()
            resolved_host = host or self.settings.host
            resolved_port = self.settings.port if port is None else port
            resolved_timeout = timeout or self.settings.timeout_seconds

            sock = socket.create_connection(
                (resolved_host, resolved_port),
                timeout=resolved_timeout,
            )
            sock.settimeout(resolved_timeout)
            self._sock = sock
            self._framer = MessageFramer(
                sock,
                max_message_bytes=self.settings.max_message_bytes,
            )
            self._host = resolved_host
            self._port = resolved_port

            info = self.crypto.describe()
            logger.info(
                "Подключено к %s:%s algorithm=%s key_id=%s key_fingerprint=%s",
                resolved_host,
                resolved_port,
                info["algorithm"],
                info["key_id"],
                info["key_fingerprint"],
            )

    def close(self) -> None:
        with self._lock:
            sock = self._sock
            self._sock = None
            self._framer = None
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    @property
    def connected(self) -> bool:
        return self._sock is not None

    def __enter__(self) -> "BankingClient":
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    # ── Обмен ────────────────────────────────────────────────────────────

    def _ensure_connected(self) -> tuple[socket.socket, MessageFramer]:
        if self._sock is None or self._framer is None:
            raise ConnectionError("client is not connected")
        return self._sock, self._framer

    def request(
        self,
        request: Request,
        *,
        timeout: float | None = None,
        max_retries: int | None = None,
    ) -> Response:
        """Шифрует запрос, отправляет и возвращает расшифрованный ответ."""
        with self._lock:
            sock, framer = self._ensure_connected()
            response, req_env, resp_env = _request_loop(
                sock,
                framer,
                self.protocol,
                request,
                max_retries=(
                    max_retries
                    if max_retries is not None
                    else self.settings.max_retries
                ),
                timeout=timeout or self.settings.timeout_seconds,
            )
            self.last_request_envelope = req_env
            self.last_response_envelope = resp_env
            return response

    def send_envelope(
        self,
        envelope: EncryptedMessage,
        *,
        timeout: float | None = None,
    ) -> Response:
        """Отправляет готовый конверт (для экспериментов с подменой данных)."""
        with self._lock:
            sock, framer = self._ensure_connected()
            sock.settimeout(timeout or self.settings.timeout_seconds)
            framer.send(self.protocol.encode(envelope))

            raw = framer.recv()
            if raw is None:
                raise ConnectionError("Server closed connection")

            response_envelope = self.protocol.decode(raw)
            self.last_response_envelope = response_envelope
            message = self.protocol.open(response_envelope)
            if not isinstance(message, Response):
                raise ProtocolError(
                    ErrorCode.INVALID_REQUEST,
                    "Expected response, got request",
                )
            return message

    def send_raw(self, raw: bytes) -> None:
        """Отправляет сырые байты (негативные тесты формата)."""
        with self._lock:
            sock, _ = self._ensure_connected()
            sock.sendall(raw)


# ─────────────────────────────────────────────────────────────────────────────
# Демонстрационный сценарий
# ─────────────────────────────────────────────────────────────────────────────

def _show_response(
    name: str,
    response: Response,
    client: BankingClient,
) -> None:
    logger.info("%s response: %s", name, response.to_dict())
    envelope = client.last_response_envelope
    if envelope is not None:
        logger.info(
            "%s security: key_id=%s nonce=%s ciphertext_bytes=%s tag=%s",
            name,
            envelope.key_id,
            envelope.nonce.hex(),
            len(envelope.ciphertext),
            envelope.tag.hex(),
        )


def main() -> None:
    settings = get_settings()
    setup_logging(LOGGER_NAME, settings)
    logger.info("Конфигурация: %s", settings.safe_summary())

    with BankingClient(settings) as client:
        client.connect()

        # 1. Обычный обмен
        for name, request in (
            ("HELLO", Request(type=MessageType.HELLO)),
            (
                "ACCOUNT_GET",
                Request(
                    type=MessageType.ACCOUNT_GET,
                    payload={"account_id": "ACC-1001"},
                ),
            ),
            ("PING", Request(type=MessageType.PING)),
        ):
            _show_response(name, client.request(request), client)

        # 2. Перевод и проверка баланса
        transfer = Request(
            type=MessageType.TRANSFER,
            payload={
                "from": "ACC-1001",
                "to": "ACC-1002",
                "amount": 500.0,
            },
        )
        _show_response("TRANSFER", client.request(transfer), client)
        _show_response(
            "ACCOUNT_GET after transfer",
            client.request(
                Request(
                    type=MessageType.ACCOUNT_GET,
                    payload={"account_id": "ACC-1001"},
                )
            ),
            client,
        )

        # 3. Идемпотентный повтор: тот же request_id, но новый nonce
        replay = Request(
            type=MessageType.TRANSFER,
            request_id=transfer.request_id,
            payload=transfer.payload,
        )
        _show_response(
            "IDEMPOTENT_REPLAY", client.request(replay), client
        )

        # 4. Ошибки бизнес-логики
        for name, request in (
            (
                "NOT_FOUND",
                Request(
                    type=MessageType.ACCOUNT_GET,
                    payload={"account_id": "ACC-9999"},
                ),
            ),
            (
                "NEGATIVE_AMOUNT",
                Request(
                    type=MessageType.TRANSFER,
                    payload={
                        "from": "ACC-1001",
                        "to": "ACC-1002",
                        "amount": -100,
                    },
                ),
            ),
            (
                "INSUFFICIENT_FUNDS",
                Request(
                    type=MessageType.TRANSFER,
                    payload={
                        "from": "ACC-1001",
                        "to": "ACC-1002",
                        "amount": 999999999,
                    },
                ),
            ),
            (
                "HELLO_EXTRA_PAYLOAD",
                Request(
                    type=MessageType.HELLO,
                    payload={"foo": "bar"},
                ),
            ),
        ):
            _show_response(name, client.request(request), client)

        # 5. Неподдерживаемая версия (корректно зашифрована)
        bad_version = Request(
            type=MessageType.HELLO, version="99.0"
        )
        _show_response(
            "BAD_VERSION", client.request(bad_version), client
        )

        # 6. Эксперимент: изменение ciphertext → authentication error
        ping = Request(type=MessageType.PING)
        good_envelope = client.protocol.seal(ping)
        damaged_ciphertext = bytearray(good_envelope.ciphertext)
        damaged_ciphertext[0] ^= 0x01
        tampered = EncryptedMessage(
            version=good_envelope.version,
            request_id=good_envelope.request_id,
            kind=good_envelope.kind,
            key_id=good_envelope.key_id,
            nonce=good_envelope.nonce,
            ciphertext=bytes(damaged_ciphertext),
            tag=good_envelope.tag,
        )
        _show_response(
            "TAMPERED_CIPHERTEXT",
            client.send_envelope(tampered),
            client,
        )

        # 7. Эксперимент: изменение nonce → authentication error
        nonce_tampered = EncryptedMessage(
            version=good_envelope.version,
            request_id=good_envelope.request_id,
            kind=good_envelope.kind,
            key_id=good_envelope.key_id,
            nonce=os.urandom(12),
            ciphertext=good_envelope.ciphertext,
            tag=good_envelope.tag,
        )
        _show_response(
            "TAMPERED_NONCE",
            client.send_envelope(nonce_tampered),
            client,
        )

        # 8. Эксперимент: повторная отправка того же конверта (replay)
        replay_envelope = client.protocol.seal(Request(type=MessageType.HELLO))
        first = client.send_envelope(replay_envelope)
        _show_response("NONCE_REUSE first", first, client)
        second = client.send_envelope(replay_envelope)
        _show_response("NONCE_REUSE second", second, client)

        # 9. Таймаут и переподключение
        try:
            client.request(
                Request(type=MessageType.SLOW_TEST),
                timeout=2.0,
                max_retries=1,
            )
        except TimeoutError as exc:
            logger.error("TIMEOUT_TEST status=CONFIRMED error=%s", exc)

    # После таймаута — новое соединение.
    with BankingClient(settings) as client:
        client.connect()
        _show_response(
            "HELLO after reconnect",
            client.request(Request(type=MessageType.HELLO)),
            client,
        )
        logger.info("Все сценарии ЛР3 выполнены")


if __name__ == "__main__":
    main()
