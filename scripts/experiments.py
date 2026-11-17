"""Автоматическая демонстрация экспериментов ЛР3.

Запуск:
    uv run python scripts/experiments.py

Сценарии:
    1. Обычный защищённый обмен.
    2. Изменение ciphertext → authentication error.
    3. Изменение nonce → authentication error.
    4. Неправильный ключ → сервер отклоняет сообщение.
    5. Повторное использование nonce (replay) → отклонено.
    6. Уникальность nonce для последовательных сообщений.
    7. Сравнение трафика «ЛР2 (открытый JSON)» и «ЛР3 (конверт)».
"""

from __future__ import annotations

import base64
import json
import os
import socket
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from client.client import BankingClient
from config import get_settings
from crypto.crypto_service import CryptoService
from crypto.errors import AuthenticationError
from crypto.key_manager import KeyManager
from logging_setup import setup_logging
from protocol.codec import MessageFramer
from protocol.messages import EncryptedMessage, MessageType, Request
from protocol.secure import BankingProtocol
from server.server import BankingServer


def section(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def flip_byte(data: bytes, index: int = 0) -> bytes:
    result = bytearray(data)
    result[index] ^= 0x01
    return bytes(result)


def mutate(
    envelope: EncryptedMessage,
    **overrides: str,
) -> EncryptedMessage:
    data = envelope.to_dict()
    data.update(overrides)
    return EncryptedMessage.from_dict(data)


def show_envelope(name: str, envelope: EncryptedMessage) -> None:
    print(
        f"{name}: key_id={envelope.key_id} "
        f"nonce={len(envelope.nonce)}B ciphertext={len(envelope.ciphertext)}B "
        f"tag={len(envelope.tag)}B wire={envelope.wire_size}B"
    )


def main() -> None:
    settings = get_settings()
    setup_logging("server.server", settings)
    setup_logging("client.client", settings)

    server = BankingServer(settings)
    port = server.start_background()
    print(f"Сервер запущен на 127.0.0.1:{port}")

    try:
        with BankingClient(settings) as client:
            client.connect(port=port)

            section("Эксперимент 1. Обычный защищённый обмен")
            response = client.request(Request(type=MessageType.HELLO))
            show_envelope(
                "запрос", client.last_request_envelope  # type: ignore[arg-type]
            )
            show_envelope(
                "ответ", client.last_response_envelope  # type: ignore[arg-type]
            )
            print(f"status={response.status} payload={response.to_dict().get('payload')}")

            section("Эксперимент 2. Изменение ciphertext")
            envelope = client.protocol.seal(Request(type=MessageType.PING))
            tampered = mutate(
                envelope,
                ciphertext=base64.b64encode(
                    flip_byte(envelope.ciphertext)
                ).decode("ascii"),
            )
            response = client.send_envelope(tampered)
            print(
                f"status={response.status} "
                f"code={response.error.code if response.error else '-'}"
            )
            print(
                "Ожидаемо: сервер обнаружил изменение и отклонил сообщение "
                "(AUTH_FAILED)."
            )

            section("Эксперимент 3. Изменение nonce")
            fresh = client.protocol.seal(Request(type=MessageType.PING))
            new_nonce = os.urandom(12)
            while new_nonce == fresh.nonce:
                new_nonce = os.urandom(12)
            tampered_nonce = mutate(
                fresh,
                nonce=base64.b64encode(new_nonce).decode("ascii"),
            )
            response = client.send_envelope(tampered_nonce)
            print(
                f"status={response.status} "
                f"code={response.error.code if response.error else '-'}"
            )
            print("Ожидаемо: корректно расшифровать сообщение невозможно.")

            section("Эксперимент 5. Повторное использование nonce (replay)")
            replay = client.protocol.seal(Request(type=MessageType.HELLO))
            first = client.send_envelope(replay)
            second = client.send_envelope(replay)
            print(
                f"первая отправка : status={first.status}"
            )
            print(
                f"повторная       : status={second.status} "
                f"code={second.error.code if second.error else '-'}"
            )
            print("Ожидаемо: повторный nonce отклонён (защита от replay).")

            section("Эксперимент 6. Уникальность nonce")
            request = Request(type=MessageType.ACCOUNT_GET,
                              payload={"account_id": "ACC-1001"})
            nonces = [client.protocol.seal(request).nonce for _ in range(100)]
            print(f"сгенерировано nonce: {len(nonces)}")
            print(f"уникальных nonce   : {len(set(nonces))}")
            print("Ожидаемо: 100 из 100 (nonce не повторяются).")

            section("Эксперимент 7. Анализ трафика ЛР2 vs ЛР3")
            transfer = Request(
                type=MessageType.TRANSFER,
                payload={
                    "from": "ACC-1001",
                    "to": "ACC-1002",
                    "amount": 500.0,
                },
            )
            plaintext_wire = (
                json.dumps(transfer.to_dict(), ensure_ascii=False).encode() + b"\n"
            )
            secure_envelope = client.protocol.seal(transfer)
            secure_wire = client.protocol.encode(secure_envelope)

            print(f"ЛР2: {len(plaintext_wire)} байт открытого JSON")
            print(f"ЛР3: {len(secure_wire)} байт защищённого конверта")
            print(
                f"Накладные расходы: +{len(secure_wire) - len(plaintext_wire)} "
                "байт (nonce + tag + base64 + метаданные)"
            )

            markers = [
                b"ACC-1001",
                b"ACC-1002",
                b"500.0",
                b"TRANSFER",
                b"payload",
            ]
            leaked = [marker.decode() for marker in markers if marker in secure_wire]
            print(f"Видимые прикладные данные в ЛР3: {leaked or 'нет'}")
            print(
                "В ЛР3 видны только метаданные конверта: version, request_id, "
                "kind, key_id, nonce, ciphertext, tag."
            )
            print(
                f"Размер nonce={len(secure_envelope.nonce)}B, "
                f"tag={len(secure_envelope.tag)}B, "
                f"key_id={secure_envelope.key_id}."
            )

        section("Эксперимент 4. Неправильный ключ")
        wrong_key = os.urandom(32)
        # Тот же key_id, но другой ключ — имитация неверной конфигурации.
        wrong_keys = KeyManager.from_key(wrong_key, settings.key_id)
        wrong_protocol = BankingProtocol(CryptoService(wrong_keys))

        with socket.create_connection(
            ("127.0.0.1", port), timeout=settings.timeout_seconds
        ) as sock:
            framer = MessageFramer(
                sock, max_message_bytes=settings.max_message_bytes
            )
            envelope = wrong_protocol.seal(Request(type=MessageType.HELLO))
            framer.send(wrong_protocol.encode(envelope))
            raw = framer.recv()
            print(f"Сервер ответил: {len(raw or b'')} байт")
            try:
                wrong_protocol.open(wrong_protocol.decode(raw or b""))
            except AuthenticationError:
                print(
                    "Ожидаемо: ответ сервера не прошёл проверку tag — "
                    "стороны используют разные ключи."
                )
            else:
                print("НЕОЖИДАННО: сообщение расшифровано неправильным ключом!")

        section("ИТОГ")
        print("Все обязательные эксперименты ЛР3 выполнены.")
        print(
            "Ключ не выводился в консоль и журналы; для каждого сообщения "
            "использовался новый nonce; изменение данных обнаруживается."
        )

    finally:
        server.stop()


if __name__ == "__main__":
    main()
