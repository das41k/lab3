"""Кадрирование сообщений поверх TCP.

Протокол использует построчный JSON: одно сообщение — одна строка,
завершающаяся '\\n'. Класс :class:`MessageFramer` инкапсулирует буфер и
контроль максимального размера, защищая сервер от слишком больших
входящих сообщений.
"""

from __future__ import annotations

import socket

from protocol.messages import MessageTooLargeError

DEFAULT_MAX_MESSAGE_BYTES = 64 * 1024


class MessageFramer:
    """Читает/пишет '\\n'-разделённые кадры с ограничением размера."""

    def __init__(
        self,
        sock: socket.socket,
        *,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        recv_size: int = 4096,
    ) -> None:
        if max_message_bytes <= 0:
            raise ValueError("max_message_bytes must be positive")
        self._sock = sock
        self._max = max_message_bytes
        self._recv_size = recv_size
        self._buffer = bytearray()

    @property
    def max_message_bytes(self) -> int:
        return self._max

    def send(self, payload: bytes) -> None:
        """Отправляет кадр (добавляет '\\n', если его нет)."""
        if not payload:
            raise ValueError("empty payload")
        frame = payload if payload.endswith(b"\n") else payload + b"\n"
        if len(frame) > self._max:
            raise MessageTooLargeError(len(frame), self._max)
        self._sock.sendall(frame)

    def recv(self) -> bytes | None:
        """Читает один кадр.

        Возвращает ``None`` при штатном закрытии соединения. Пустые строки
        пропускаются. При превышении лимита выбрасывает
        :class:`MessageTooLargeError`.
        """
        while True:
            newline = self._buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self._buffer[:newline])
                del self._buffer[: newline + 1]
                if not frame.strip():
                    continue
                if len(frame) > self._max:
                    raise MessageTooLargeError(len(frame), self._max)
                return frame

            if len(self._buffer) > self._max:
                raise MessageTooLargeError(len(self._buffer), self._max)

            chunk = self._sock.recv(self._recv_size)
            if not chunk:
                if self._buffer:
                    raise ConnectionError(
                        "connection closed before message delimiter"
                    )
                return None
            self._buffer.extend(chunk)
