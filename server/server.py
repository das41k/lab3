"""TCP-сервер Banking Protocol с AES-GCM-защитой (ЛР3).

Сервер отвечает только за сеть и оркестрацию:

    socket → MessageFramer → BankingProtocol.open() → OrderService.handle()
           → BankingProtocol.seal() → MessageFramer.send()

Криптография, формат сообщений и бизнес-логика вынесены в отдельные
модули (crypto/, protocol/, service/).
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import socket
import sys
import threading
from pathlib import Path

# Возможность запускать как `python server/server.py` из корня проекта.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import Settings, get_settings
from crypto.crypto_service import CryptoService
from crypto.errors import CryptoError
from crypto.key_manager import KeyManager
from logging_setup import setup_logging
from protocol.codec import MessageFramer
from protocol.messages import (
    PROTOCOL_VERSION,
    ErrorCode,
    MessageTooLargeError,
    ProtocolError,
    Request,
    Response,
    UnsupportedVersionError,
)
from protocol.secure import BankingProtocol
from service.order_service import OrderService

logger = logging.getLogger(__name__)


def _nonce_tag(nonce: bytes) -> str:
    """Короткий отпечаток nonce для журнала (nonce не секретен)."""
    return hashlib.sha256(nonce).hexdigest()[:8]


class BankingServer:
    """Многопоточный сервер с предварительно распределённым ключом."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        key_manager: KeyManager | None = None,
        service: OrderService | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.keys = key_manager or KeyManager(self.settings)
        self.crypto = CryptoService(
            self.keys,
            strict_nonce_check=self.settings.strict_nonce_check,
        )
        self.protocol = BankingProtocol(
            self.crypto,
            max_message_bytes=self.settings.max_message_bytes,
        )
        self.service = service or OrderService(
            slow_test_seconds=self.settings.slow_test_seconds
        )

        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    # ── Жизненный цикл ───────────────────────────────────────────────────

    def start_background(
        self,
        host: str | None = None,
        port: int | None = None,
    ) -> int:
        """Занимает порт и запускает accept-loop в фоновом потоке.

        Возвращает фактический порт (полезно при ``port=0``).
        """
        if self._listener is not None:
            raise RuntimeError("server is already running")

        host = host or self.settings.host
        port = self.settings.port if port is None else port

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, port))
        listener.listen()
        listener.settimeout(0.5)
        self._listener = listener
        self._stop_event.clear()

        actual_port = listener.getsockname()[1]
        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            args=(listener,),
            name="banking-server-accept",
            daemon=True,
        )
        self._accept_thread.start()

        info = self.crypto.describe()
        logger.info(
            "Сервер запущен на %s:%s algorithm=%s key_id=%s "
            "key_fingerprint=%s",
            host,
            actual_port,
            info["algorithm"],
            info["key_id"],
            info["key_fingerprint"],
        )
        return actual_port

    def serve_forever(
        self,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        self.start_background(host, port)
        try:
            while not self._stop_event.wait(0.5):
                pass
        except KeyboardInterrupt:
            logger.info("Получен SIGINT, сервер останавливается")
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop_event.set()
        listener = self._listener
        self._listener = None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        thread = self._accept_thread
        self._accept_thread = None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        logger.info("Сервер остановлен")

    # ── Сеть ─────────────────────────────────────────────────────────────

    def _accept_loop(self, listener: socket.socket) -> None:
        while not self._stop_event.is_set():
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()

    def _handle_client(
        self,
        conn: socket.socket,
        addr: tuple[str, int],
    ) -> None:
        logger.info("Клиент подключился: %s:%s", *addr)
        framer = MessageFramer(
            conn,
            max_message_bytes=self.settings.max_message_bytes,
        )
        try:
            while True:
                try:
                    raw = framer.recv()
                except MessageTooLargeError as exc:
                    logger.warning(
                        "addr=%s:%s status=MESSAGE_TOO_LARGE size=%s limit=%s",
                        *addr,
                        exc.size,
                        exc.limit,
                    )
                    self._send_response(
                        framer,
                        Response.failure(
                            "UNKNOWN",
                            ErrorCode.MESSAGE_TOO_LARGE,
                            "Message too large",
                        ),
                    )
                    break

                if raw is None:
                    break
                self._process_message(framer, raw)
        except ConnectionResetError:
            logger.warning("Соединение сброшено клиентом %s:%s", *addr)
        except (ConnectionError, OSError) as exc:
            logger.warning("Сетевая ошибка %s:%s: %s", *addr, exc)
        except Exception:  # noqa: BLE001 - последний барьер сервера
            logger.exception("Необработанная ошибка клиента %s:%s", *addr)
        finally:
            try:
                conn.close()
            except OSError:
                pass
            logger.info("Клиент отключился: %s:%s", *addr)

    # ── Обработка одного сообщения ───────────────────────────────────────

    def _process_message(
        self,
        framer: MessageFramer,
        raw: bytes,
    ) -> None:
        request_id = "UNKNOWN"
        message_type = "UNKNOWN"
        key_id = "-"
        nonce_tag = "-"

        try:
            envelope = self.protocol.decode(raw)
            request_id = envelope.request_id
            key_id = envelope.key_id
            nonce_tag = _nonce_tag(envelope.nonce)

            message = self.protocol.open(envelope)
            if not isinstance(message, Request):
                raise ProtocolError(
                    ErrorCode.INVALID_REQUEST,
                    "Expected request, got response",
                )

            request_id = message.request_id
            message_type = message.type
            logger.info(
                "request_id=%s type=%s status=RECEIVED key_id=%s nonce=%s",
                request_id,
                message_type,
                key_id,
                nonce_tag,
            )

            if message.version != PROTOCOL_VERSION:
                raise UnsupportedVersionError(message.version)

            response = self.service.handle(message)

        except CryptoError as exc:
            # Не раскрываем детали (какой именно тег/ключ) в ответе.
            logger.warning(
                "request_id=%s type=%s status=AUTH_FAILED key_id=%s "
                "nonce=%s reason=%s",
                request_id,
                message_type,
                key_id,
                nonce_tag,
                type(exc).__name__,
            )
            response = Response.failure(
                request_id,
                ErrorCode.AUTH_FAILED,
                "Message authentication failed",
            )
        except ProtocolError as exc:
            logger.warning(
                "request_id=%s type=%s status=%s detail=%s",
                request_id,
                message_type,
                exc.code,
                exc.message,
            )
            response = Response.failure(
                request_id, exc.code, exc.message
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "request_id=%s type=%s status=INTERNAL_ERROR",
                request_id,
                message_type,
            )
            response = Response.failure(
                request_id,
                ErrorCode.INTERNAL_ERROR,
                "Internal server error",
            )

        self._send_response(framer, response)

    def _send_response(
        self,
        framer: MessageFramer,
        response: Response,
    ) -> None:
        try:
            envelope = self.protocol.seal(response)
            framer.send(self.protocol.encode(envelope))
            logger.info(
                "request_id=%s status=%s key_id=%s nonce=%s bytes=%s",
                response.request_id,
                response.status,
                envelope.key_id,
                _nonce_tag(envelope.nonce),
                envelope.wire_size,
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "request_id=%s status=ENCRYPT_RESPONSE_FAILED",
                response.request_id,
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Banking Protocol server")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    settings = get_settings()
    setup_logging("server.server", settings)
    logger.info("Конфигурация: %s", settings.safe_summary())

    server = BankingServer(settings)
    server.serve_forever(args.host, args.port)


if __name__ == "__main__":
    main()
