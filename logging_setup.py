"""Единая настройка журналирования.

Правило ЛР3: в журналы попадают только метаданные (request_id, type,
status, key_id, короткий отпечаток nonce). Ключи и открытый текст
секретных данных не журналируются.
"""

from __future__ import annotations

import logging

from config import Settings, get_settings


def setup_logging(
    component: str,
    settings: Settings | None = None,
    level: int = logging.INFO,
) -> logging.Logger:
    """Настраивает файловый и консольный обработчики для ``component``."""
    settings = settings or get_settings()
    logger = logging.getLogger(component)

    if getattr(logger, "_bsp_logging_configured", False):
        return logger

    settings.log_dir.mkdir(parents=True, exist_ok=True)
    log_file = settings.log_dir / f"{component.rsplit('.', 1)[-1]}.log"

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.setLevel(level)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    logger.propagate = False
    logger._bsp_logging_configured = True  # type: ignore[attr-defined]
    return logger
