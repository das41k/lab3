"""Генерация AES-256 ключа и сохранение его в локальный .env.

Ключ печатается только в виде SHA-256-отпечатка. Сам ключ записывается
в .env, который исключён из Git (.gitignore).

Запуск:
    uv run python scripts/generate_key.py
    uv run python scripts/generate_key.py --key-id key-2026-02
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import PROJECT_ROOT
from crypto.constants import KEY_SIZE
from crypto.key_manager import key_fingerprint

DEFAULT_ENV_TEMPLATE = """\
APP_HOST=127.0.0.1
APP_PORT=65432
APP_KEY_ID=key-2026-01
APP_ENCRYPTION_KEY=
APP_KEYRING_FILE=keys/keyring.json
APP_MAX_MESSAGE_BYTES=65536
APP_TIMEOUT_SECONDS=5
APP_MAX_RETRIES=3
APP_STRICT_NONCE_CHECK=true
APP_SLOW_TEST_SECONDS=30
APP_LOG_DIR=logs
"""


def upsert_env(text: str, values: dict[str, str]) -> str:
    """Обновляет KEY=VALUE, не трогая комментарии и прочие строки."""
    lines = text.splitlines()
    remaining = dict(values)
    result: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                result.append(f"{key}={remaining.pop(key)}")
                continue
        result.append(line)

    for key, value in remaining.items():
        result.append(f"{key}={value}")

    return "\n".join(result) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate AES-256 key")
    parser.add_argument(
        "--key-id",
        default=f"key-{datetime.now(timezone.utc):%Y-%m}",
        help="идентификатор версии ключа",
    )
    args = parser.parse_args()

    env_path = PROJECT_ROOT / ".env"
    example_path = PROJECT_ROOT / ".env.example"

    if env_path.exists():
        text = env_path.read_text(encoding="utf-8")
    elif example_path.exists():
        text = example_path.read_text(encoding="utf-8")
    else:
        text = DEFAULT_ENV_TEMPLATE

    key = os.urandom(KEY_SIZE)
    encoded = base64.b64encode(key).decode("ascii")

    text = upsert_env(
        text,
        {
            "APP_KEY_ID": args.key_id,
            "APP_ENCRYPTION_KEY": encoded,
        },
    )
    env_path.write_text(text, encoding="utf-8")

    print("Ключ сохранён в .env (файл исключён из Git).")
    print(f"key_id      : {args.key_id}")
    print(f"fingerprint : {key_fingerprint(key)}")
    print("Сам ключ в консоль не выводится.")


if __name__ == "__main__":
    main()
