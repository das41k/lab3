"""Симметричное шифрование AES-256-GCM (AEAD).

Используется промышленная библиотека ``cryptography`` — собственная
реализация AES запрещена условиями ЛР3.

Каждое сообщение получает новый случайный nonce (12 байт). Для каждого
ключа ведётся учёт использованных nonce; повторное использование
обнаруживается и приводит к :class:`NonceReuseError`.
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.constants import ALGORITHM, KEY_SIZE, NONCE_SIZE, TAG_SIZE
from crypto.errors import AuthenticationError, NonceReuseError
from crypto.key_manager import KeyManager, key_fingerprint


@dataclass(frozen=True)
class SealedPayload:
    """Результат шифрования: nonce + ciphertext + authentication tag."""

    nonce: bytes
    ciphertext: bytes
    tag: bytes

    def __repr__(self) -> str:  # не засоряем журналы/base64-дампами
        return (
            f"SealedPayload(nonce={self.nonce.hex()[:8]}…, "
            f"ciphertext={len(self.ciphertext)}B, "
            f"tag={self.tag.hex()[:8]}…)"
        )


class NonceTracker:
    """Ограниченный по размеру реестр использованных nonce.

    Ключ учёта — пара (key_id, nonce). При переполнении вытесняются самые
    старые записи (FIFO), что ограничивает потребление памяти.
    """

    def __init__(self, max_entries: int = 100_000) -> None:
        self._seen: OrderedDict[tuple[str, bytes], None] = OrderedDict()
        self._lock = threading.Lock()
        self._max_entries = max_entries

    def register(self, key_id: str, nonce: bytes) -> None:
        entry = (key_id, bytes(nonce))
        with self._lock:
            if entry in self._seen:
                raise NonceReuseError(
                    f"повторное использование nonce для key_id={key_id!r}"
                )
            self._seen[entry] = None
            while len(self._seen) > self._max_entries:
                self._seen.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)


class CryptoService:
    """Шифрование/расшифрование с проверкой целостности."""

    algorithm = ALGORITHM

    def __init__(
        self,
        key_manager: KeyManager,
        *,
        strict_nonce_check: bool = True,
        nonce_tracker: NonceTracker | None = None,
        incoming_nonce_tracker: NonceTracker | None = None,
    ) -> None:
        self._keys = key_manager
        self._strict = strict_nonce_check
        # Раздельные реестры: исходящие nonce (шифрование) и входящие
        # (расшифрование). Это позволяет одной стороне проверять replay,
        # не конфликтуя с собственными исходящими сообщениями.
        self._outgoing_nonces = nonce_tracker or NonceTracker()
        self._incoming_nonces = incoming_nonce_tracker or NonceTracker()

    @property
    def key_manager(self) -> KeyManager:
        return self._keys

    @property
    def current_key_id(self) -> str:
        return self._keys.current_key_id

    def describe(self) -> dict[str, object]:
        """Безопасная для журнала информация о криптоконфигурации."""
        return {
            "algorithm": self.algorithm,
            "key_id": self.current_key_id,
            "key_fingerprint": self._keys.fingerprint(),
            "strict_nonce_check": self._strict,
        }

    # ── Шифрование ───────────────────────────────────────────────────────

    def generate_nonce(self) -> bytes:
        """Криптостойкий nonce: 12 случайных байт от os.urandom."""
        return os.urandom(NONCE_SIZE)

    def encrypt(
        self,
        plaintext: bytes,
        *,
        aad: bytes = b"",
        key_id: str | None = None,
        nonce: bytes | None = None,
    ) -> SealedPayload:
        """Шифрует ``plaintext`` и возвращает nonce/ciphertext/tag.

        ``nonce`` можно передать явно только для тестов/экспериментов;
        повторное использование nonce с тем же ключом будет отклонено.
        """
        resolved_key_id = key_id or self.current_key_id
        key = self._keys.key_for(resolved_key_id)

        resolved_nonce = self.generate_nonce() if nonce is None else bytes(nonce)
        if len(resolved_nonce) != NONCE_SIZE:
            raise ValueError(
                f"nonce должен быть длиной {NONCE_SIZE} байт"
            )

        # Учёт nonce: правило «новое сообщение → новый nonce».
        if self._strict:
            self._outgoing_nonces.register(resolved_key_id, resolved_nonce)

        sealed = AESGCM(key).encrypt(resolved_nonce, plaintext, aad)
        ciphertext = sealed[:-TAG_SIZE]
        tag = sealed[-TAG_SIZE:]
        if len(tag) != TAG_SIZE:  # защитная проверка инварианта
            raise AuthenticationError("некорректный размер authentication tag")
        return SealedPayload(
            nonce=resolved_nonce,
            ciphertext=ciphertext,
            tag=tag,
        )

    # ── Расшифрование ────────────────────────────────────────────────────

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        *,
        aad: bytes = b"",
        key_id: str | None = None,
    ) -> bytes:
        """Проверяет tag и расшифровывает сообщение.

        При изменении ciphertext/nonce/tag/AAD выбрасывает
        :class:`AuthenticationError`. Повторно полученный nonce (replay)
        обнаруживается после успешной аутентификации.
        """
        if len(nonce) != NONCE_SIZE:
            raise AuthenticationError("некорректная длина nonce")
        if len(tag) != TAG_SIZE:
            raise AuthenticationError("некорректная длина authentication tag")

        resolved_key_id = key_id or self.current_key_id
        key = self._keys.key_for(resolved_key_id)

        try:
            plaintext = AESGCM(key).decrypt(
                nonce, bytes(ciphertext) + bytes(tag), aad
            )
        except InvalidTag as exc:
            raise AuthenticationError(
                "проверка authentication tag не пройдена"
            ) from exc

        # Регистрируем nonce только после успешной аутентификации, чтобы
        # подделанные сообщения не «отравляли» реестр.
        if self._strict:
            self._incoming_nonces.register(resolved_key_id, nonce)
        return plaintext

    # ── Диагностика ──────────────────────────────────────────────────────

    @staticmethod
    def fingerprint_key(key: bytes) -> str:
        return key_fingerprint(key)

    @staticmethod
    def expected_key_size() -> int:
        return KEY_SIZE
