"""Банковская бизнес-логика, независимая от сети и криптографии.

Сервер только принимает защищённые конверты и передаёт расшифрованный
:class:`Request` в :class:`OrderService`. Такое разделение соответствует
требованию ЛР3 о Separation of Concerns.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Mapping

from protocol.messages import (
    ErrorCode,
    MessageType,
    ProtocolError,
    Request,
    Response,
)

DEFAULT_ACCOUNTS: dict[str, dict[str, Any]] = {
    "ACC-1001": {"owner": "Ivanov",  "balance": 10000.0},
    "ACC-1002": {"owner": "Petrov",  "balance": 5000.0},
    "ACC-1003": {"owner": "Sidorov", "balance": 2500.0},
}


@dataclass
class Account:
    owner: str
    balance: float


class OrderService:
    """Обрабатывает запросы протокола и хранит состояние счетов."""

    def __init__(
        self,
        accounts: Mapping[str, Mapping[str, Any]] | None = None,
        *,
        slow_test_seconds: float = 30.0,
    ) -> None:
        self._lock = threading.RLock()
        self._slow_test_seconds = slow_test_seconds
        self._accounts: dict[str, Account] = {}
        self._idempotency: dict[str, Response] = {}
        self.reset(accounts)

    # ── Состояние (используется тестами) ─────────────────────────────────

    def reset(
        self,
        accounts: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        source = accounts if accounts is not None else DEFAULT_ACCOUNTS
        with self._lock:
            self._accounts = {
                account_id: Account(
                    owner=str(data["owner"]),
                    balance=float(data["balance"]),
                )
                for account_id, data in source.items()
            }
            self._idempotency.clear()

    def balance(self, account_id: str) -> float:
        with self._lock:
            account = self._accounts.get(account_id)
            if account is None:
                raise KeyError(account_id)
            return account.balance

    def snapshot(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {
                account_id: {
                    "owner": account.owner,
                    "balance": account.balance,
                }
                for account_id, account in self._accounts.items()
            }

    # ── Обработка запросов ───────────────────────────────────────────────

    def handle(self, request: Request) -> Response:
        """Возвращает :class:`Response` на валидный запрос."""
        if not isinstance(request, Request):
            raise TypeError(f"expected Request, got {type(request)!r}")

        message_type = request.type
        payload = request.payload
        request_id = request.request_id

        if message_type is MessageType.HELLO:
            return Response.success(
                request_id,
                {"message": "Welcome to Banking System"},
            )

        if message_type is MessageType.PING:
            return Response.success(
                request_id,
                {"type": MessageType.PONG.value},
            )

        if message_type is MessageType.ACCOUNT_GET:
            account_id = payload.get("account_id")
            if not account_id:
                raise ProtocolError(
                    ErrorCode.INVALID_REQUEST, "Missing account_id"
                )
            with self._lock:
                account = self._accounts.get(str(account_id))
                if account is None:
                    raise ProtocolError(
                        ErrorCode.RESOURCE_NOT_FOUND, "Account not found"
                    )
                return Response.success(
                    request_id,
                    {
                        "account_id": account_id,
                        "balance": account.balance,
                    },
                )

        if message_type is MessageType.TRANSFER:
            return self._handle_transfer(request)

        if message_type is MessageType.SLOW_TEST:
            # Сон вне блокировки: остальные клиенты продолжают обслуживаться.
            time.sleep(self._slow_test_seconds)
            return Response.success(
                request_id, {"message": "Slow response"}
            )

        raise ProtocolError(
            ErrorCode.INVALID_REQUEST, "Unsupported message type"
        )

    def _handle_transfer(self, request: Request) -> Response:
        payload = request.payload
        request_id = request.request_id

        with self._lock:
            cached = self._idempotency.get(request_id)
            if cached is not None:
                return cached

            from_acc = payload.get("from")
            to_acc = payload.get("to")
            amount = payload.get("amount")

            if from_acc is None or to_acc is None or amount is None:
                raise ProtocolError(
                    ErrorCode.INVALID_REQUEST,
                    "Missing transfer parameters (from, to, amount)",
                )
            if not isinstance(amount, (int, float)) or isinstance(amount, bool):
                raise ProtocolError(
                    ErrorCode.INVALID_DATA,
                    "Amount must be a positive number",
                )
            if amount <= 0:
                raise ProtocolError(
                    ErrorCode.INVALID_DATA,
                    "Amount must be a positive number",
                )

            from_account = self._accounts.get(str(from_acc))
            to_account = self._accounts.get(str(to_acc))
            if from_account is None:
                raise ProtocolError(
                    ErrorCode.RESOURCE_NOT_FOUND,
                    "Source account not found",
                )
            if to_account is None:
                raise ProtocolError(
                    ErrorCode.RESOURCE_NOT_FOUND,
                    "Destination account not found",
                )
            if from_acc == to_acc:
                raise ProtocolError(
                    ErrorCode.INVALID_DATA,
                    "Cannot transfer to the same account",
                )
            if from_account.balance < amount:
                raise ProtocolError(
                    ErrorCode.INVALID_DATA, "Insufficient funds"
                )

            from_account.balance -= amount
            to_account.balance += amount

            response = Response.success(
                request_id,
                {
                    "message": "Transfer completed",
                    "from": from_acc,
                    "to": to_acc,
                    "amount": amount,
                    "new_balance": from_account.balance,
                },
            )
            # Идемпотентность: повтор с тем же request_id не спишет деньги.
            self._idempotency[request_id] = response
            return response
