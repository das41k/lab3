"""Ротация ключа без изменения исходного кода.

Создаёт новый ключ в keys/keyring.json, делает его текущим и обновляет
локальный .env. Старые ключи остаются в keyring, поэтому сервер может
расшифровать сообщения, отправленные до ротации.

Запуск:
    uv run python scripts/rotate_key.py
    uv run python scripts/rotate_key.py --key-id key-2026-02
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import PROJECT_ROOT, get_settings
from crypto.key_manager import KeyManager, encode_key, key_fingerprint
from scripts.generate_key import DEFAULT_ENV_TEMPLATE, upsert_env


def unique_key_id(manager: KeyManager, base: str) -> str:
    candidate = base
    suffix = 2
    while manager.has_key(candidate):
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def main() -> None:
    parser = argparse.ArgumentParser(description="Rotate AES-256 key")
    parser.add_argument(
        "--key-id",
        default=f"key-{datetime.now(timezone.utc):%Y-%m}",
        help="идентификатор новой версии ключа",
    )
    args = parser.parse_args()

    settings = get_settings()
    manager = KeyManager(settings)

    old_key_id = manager.current_key_id
    old_fingerprint = manager.fingerprint(old_key_id)

    new_key_id = unique_key_id(manager, args.key_id)
    manager.rotate(new_key_id)
    new_key = manager.key_for(new_key_id)

    env_path = PROJECT_ROOT / ".env"
    text = (
        env_path.read_text(encoding="utf-8")
        if env_path.exists()
        else DEFAULT_ENV_TEMPLATE
    )
    text = upsert_env(
        text,
        {
            "APP_KEY_ID": new_key_id,
            "APP_ENCRYPTION_KEY": encode_key(new_key),
        },
    )
    env_path.write_text(text, encoding="utf-8")

    print("Ротация ключа выполнена.")
    print(f"old key_id  : {old_key_id} (fingerprint {old_fingerprint})")
    print(f"new key_id  : {new_key_id} (fingerprint {key_fingerprint(new_key)})")
    print("Старый ключ сохранён в keyring и доступен только для расшифрования.")
    print("Новый ключ записан в .env; исходный код менять не требуется.")

    if os.environ.get("APP_ENCRYPTION_KEY"):
        print(
            "ВНИМАНИЕ: APP_ENCRYPTION_KEY задан в окружении ОС и имеет "
            "приоритет над .env. Обновите переменную окружения вручную."
        )


if __name__ == "__main__":
    main()
