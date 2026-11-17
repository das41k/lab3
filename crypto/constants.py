"""Параметры симметричной криптографии (AES-256-GCM)."""

from __future__ import annotations

# Промышленная реализация: cryptography.hazmat.primitives.ciphers.aead.AESGCM
ALGORITHM = "AES-256-GCM"

KEY_SIZE = 32        # 256 бит
NONCE_SIZE = 12      # 96 бит — рекомендуемый размер nonce для GCM
TAG_SIZE = 16        # 128 бит — authentication tag
