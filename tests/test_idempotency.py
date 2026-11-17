"""Тесты идемпотентности, таймаутов и ретраев (обновлено для ЛР3)."""

from __future__ import annotations

import logging
import socket
import threading
import time

import pytest

from client.client import BankingClient, send_request
from protocol.messages import MessageType, Request


class DummySilentServer:
    """Принимает TCP-соединение, но никогда не отвечает."""

    def __init__(self) -> None:
        self._server_socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        self._server_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        self._server_socket.bind(("127.0.0.1", 0))
        self._server_socket.listen(5)
        self.port = self._server_socket.getsockname()[1]
        self._running = True
        self._connections: list[socket.socket] = []

    def start(self) -> None:
        def run() -> None:
            while self._running:
                try:
                    self._server_socket.settimeout(0.5)
                    conn, _addr = self._server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._connections.append(conn)
                try:
                    conn.recv(4096)
                except OSError:
                    pass

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        try:
            self._server_socket.close()
        except OSError:
            pass
        for conn in self._connections:
            try:
                conn.close()
            except OSError:
                pass


@pytest.fixture
def dummy_server():
    server = DummySilentServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def test_timeout_triggers_retry_and_eventually_fails(
    dummy_server: DummySilentServer,
    protocol,
    caplog,
) -> None:
    with socket.create_connection(
        ("127.0.0.1", dummy_server.port), timeout=2.0
    ) as sock:
        with caplog.at_level(logging.INFO, logger="client.client"):
            with pytest.raises(TimeoutError) as context:
                send_request(
                    sock,
                    Request(type=MessageType.HELLO),
                    protocol,
                    max_retries=2,
                    timeout=0.4,
                )

    assert "Timeout after 2 attempts" in str(context.value)

    log_output = caplog.text
    assert "status=SENDING attempt=1" in log_output
    assert "status=TIMEOUT attempt=1/2" in log_output
    assert "status=RETRYING" in log_output
    assert "status=SENDING attempt=2" in log_output
    assert "status=TIMEOUT attempt=2/2" in log_output
    assert "status=ALL_RETRIES_FAILED" in log_output


def test_successful_request_after_timeout(server, settings) -> None:
    _srv, port = server

    first = BankingClient(settings)
    first.connect(port=port)
    with pytest.raises(TimeoutError):
        first.request(
            Request(type=MessageType.SLOW_TEST),
            timeout=0.3,
            max_retries=1,
        )
    first.close()

    second = BankingClient(settings)
    try:
        second.connect(port=port)
        response = second.request(Request(type=MessageType.HELLO))
        assert response.is_success
        assert response.payload is not None
        assert "Welcome" in str(response.payload["message"])
    finally:
        second.close()


def test_different_request_ids_execute_twice(server, settings) -> None:
    srv, port = server
    with BankingClient(settings) as client:
        client.connect(port=port)

        for _ in range(2):
            response = client.request(
                Request(
                    type=MessageType.TRANSFER,
                    payload={
                        "from": "ACC-1001",
                        "to": "ACC-1002",
                        "amount": 500.0,
                    },
                )
            )
            assert response.is_success

        assert srv.service.balance("ACC-1001") == 9000.0
