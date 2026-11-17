# Banking Protocol — ЛР3: защищённый обмен (AES-256-GCM)

Клиент-серверное банковское приложение из ЛР2, переведённое на защищённый
обмен данными. Сообщения протокола больше не передаются открытым JSON:
каждый запрос и ответ шифруется AES-256-GCM (AEAD), для каждого сообщения
генерируется новый nonce, целостность проверяется по authentication tag.

## Что реализовано

| Требование ЛР3 | Реализация |
|---|---|
| Промышленная криптобиблиотека | `cryptography` → `AESGCM` (аналог `Cipher.getInstance("AES/GCM/NoPadding")`) |
| AES-ключ 256 бит | `crypto/crypto_service.py`, `KEY_SIZE = 32` |
| Внешний источник ключа | `.env` + `pydantic-settings` (`APP_ENCRYPTION_KEY`) |
| Новый nonce для каждого сообщения | `os.urandom(12)`, контроль повторов в `NonceTracker` |
| Шифрование JSON | `BankingProtocol.seal()` |
| Передача nonce + ciphertext + tag | `EncryptedMessage` |
| Расшифрование и проверка tag | `BankingProtocol.open()` |
| Обработка изменения ciphertext | `AuthenticationError` → `AUTH_FAILED` |
| Безопасное хранение ключа | `.env` и `keys/keyring.json` исключены из Git |
| Журналирование без ключа | логируются только `key_id`, отпечаток ключа/nonce, статусы |
| Ротация ключа | `scripts/rotate_key.py`, `KeyManager.rotate()` |
| Защита от больших сообщений | `MessageFramer` + `APP_MAX_MESSAGE_BYTES` |
| Контроль повторного nonce | `NonceReuseError` (replay отклоняется) |
| Классовая структура протокола | `ProtocolMessage`, `Request`, `Response`, `EncryptedMessage` |

## Быстрый старт

```bash
# 1. Зависимости (uv создаст .venv)
uv sync

# 2. Сгенерировать ключ в локальный .env (файл не попадает в Git)
uv run python scripts/generate_key.py

# 3. Запустить сервер
uv run python -m server.server

# 4. В другом терминале — консольный клиент
uv run python -m client.client

#    или графический клиент
uv run python -m client.client_ui
```

Тесты и эксперименты:

```bash
uv run pytest -q
uv run python scripts/experiments.py
```

Ротация ключа без изменения кода:

```bash
uv run python scripts/rotate_key.py
# или с явным идентификатором:
uv run python scripts/rotate_key.py --key-id key-2026-12
```

## Структура проекта

```
banking_protocol/
├── client/
│   ├── client.py          # BankingClient: защищённый обмен по TCP
│   └── client_ui.py       # графический клиент (Tkinter)
├── server/
│   └── server.py          # BankingServer: сеть + оркестрация
├── protocol/
│   ├── messages.py        # ProtocolMessage, Request, Response, EncryptedMessage
│   ├── secure.py          # BankingProtocol: seal/open
│   ├── codec.py           # MessageFramer: кадры и лимит размера
│   └── __init__.py
├── crypto/
│   ├── crypto_service.py  # AES-256-GCM, nonce, NonceTracker
│   ├── key_manager.py     # загрузка/хранение/ротация ключей
│   ├── constants.py
│   └── errors.py
├── service/
│   └── order_service.py   # счета, переводы, идемпотентность
├── scripts/
│   ├── generate_key.py    # генерация ключа в .env
│   ├── rotate_key.py      # ротация ключа
│   └── experiments.py     # эксперименты ЛР3 + анализ трафика
├── tests/
│   ├── test_crypto.py     # обязательные тесты crypto (1–4)
│   ├── test_protocol.py   # формат, AAD, лимиты
│   ├── test_exchange.py   # интеграционные тесты по TCP
│   └── test_idempotency.py
├── docs/REPORT.md         # отчёт по лабораторной работе
├── config.py              # pydantic-settings
├── .env.example           # шаблон без секрета (коммитится)
├── .env                   # настоящий ключ (НЕ коммитится)
├── pyproject.toml
└── uv.lock
```

## Формат защищённого сообщения

Внутри конверта лежит обычный JSON-запрос/ответ ЛР2 (UTF-8):

```json
{
  "version": "1.0",
  "request_id": "8f0c...",
  "timestamp": "2026-11-17T10:30:00+00:00",
  "type": "TRANSFER",
  "payload": {"from": "ACC-1001", "to": "ACC-1002", "amount": 500.0}
}
```

На проводе передаётся только конверт (одна строка JSON + `\n`):

```json
{
  "version": "1.0",
  "request_id": "8f0c...",
  "kind": "REQUEST",
  "key_id": "key-2026-11",
  "nonce": "base64 (12 байт)",
  "ciphertext": "base64",
  "tag": "base64 (16 байт)"
}
```

Параметры:

* алгоритм — AES-256-GCM (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`);
* ключ — 256 бит (32 байта), base64 в `APP_ENCRYPTION_KEY`;
* nonce — 96 бит (12 байт), новый для каждого сообщения;
* authentication tag — 128 бит (16 байт);
* AAD — `version | kind | request_id | key_id` (с длинами полей),
  поэтому изменение этих открытых полей ломает проверку tag;
* максимальный размер кадра — `APP_MAX_MESSAGE_BYTES` (по умолчанию 64 КиБ).

`request_id` дублируется в конверте и внутри зашифрованного сообщения;
после расшифрования протокол проверяет их совпадение. Открытыми остаются
только метаданные конверта, прикладные данные (счета, суммы, типы операций)
в трафике не видны.

## Управление ключом

1. **Генерация.** `scripts/generate_key.py` создаёт 32 случайных байта
   (`os.urandom`) и записывает base64 в `.env`; сам ключ в консоль не
   выводится — только `key_id` и короткий SHA-256-отпечаток.
2. **Хранение.** `.env` и `keys/keyring.json` перечислены в `.gitignore`.
   В репозитории есть только `.env.example` с заглушкой. Это прямое
   требование ЛР3: секрет не должен попадать в систему контроля версий.
3. **Получение.** `config.Settings` (pydantic-settings) читает `APP_*`
   из окружения/`.env`; `KeyManager` декодирует ключ, проверяет длину
   и не пишет значение в журналы.
4. **Ротация.** `KeyManager.rotate()` создаёт новый ключ и делает его
   текущим. Старые ключи остаются в `keys/keyring.json` и используются
   только для расшифрования уже отправленных сообщений. `scripts/rotate_key.py`
   обновляет `.env`, поэтому исходный код менять не нужно.
5. **Отпечаток.** В журналах допустимы `key_id` и `key_fingerprint`
   (SHA-256, 8 hex-символов). Сам ключ и его base64 не логируются.

Если ключ вообще не задан, `KeyManager` сгенерирует его и сохранит в
`keys/keyring.json` (удобно для первого запуска). Для отчёта следует
использовать вариант с `.env`.

## Что именно проверяют тесты

* `encrypt → decrypt` возвращает исходные байты;
* изменение ciphertext, tag, nonce или AAD → `AuthenticationError`;
* расшифрование неправильным ключом → `AuthenticationError`;
* 500 последовательных сообщений имеют 500 разных nonce;
* повторный nonce (включая фиксированный нулевой) → `NonceReuseError`;
* replay ранее принятого конверта отклоняется сервером (`AUTH_FAILED`);
* изменение `request_id`/`kind`/`key_id` в конверте отклоняется (AAD);
* сервер не принимает сообщения больше лимита;
* idempotency `TRANSFER` сохраняется при новом nonce;
* таймауты и повторные отправки работают как в ЛР2.

## Ограничения (важно для вывода отчёта)

В ЛР3 ключ считается **предварительно распределённым** (pre-shared key):
одинаковый ключ заранее установлен у клиента и сервера. Лабораторная
работа сознательно не решает задачу безопасного первоначального обмена
ключами. Поэтому остаются нерешёнными:

* безопасная доставка ключа при первом запуске (нужен асимметричный
  обмен / TLS, это ЛР5–ЛР6);
* взаимная аутентификация сторон (общий ключ подтверждает только знание
  ключа, но не личность);
* forward secrecy при компрометации долговременного ключа;
* защита от DoS на уровне TCP (лимит размера снижает риск, но не убирает).

При этом обеспечены конфиденциальность прикладных данных, целостность и
аутентичность сообщений (AEAD), обнаружение replay и отсутствие секретов
в трафике/журналах/исходном коде.

Подробный отчёт: [docs/REPORT.md](docs/REPORT.md).
