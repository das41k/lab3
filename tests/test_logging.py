"""Регрессия: имена логгеров должны совпадать с настройкой ``setup_logging``.

При запуске ``python -m client.client`` модуль выполняется как ``__main__``,
поэтому ``logging.getLogger(__name__)`` создавал бы отдельный логгер без
обработчиков, и сообщения терялись бы (в консоль попадали только WARNING
и ERROR через ``lastResort``).
"""

from __future__ import annotations

import logging

from config import Settings
from logging_setup import setup_logging


def test_client_entrypoint_logger_name_is_configured(settings: Settings) -> None:
    from client import client as client_module

    assert client_module.LOGGER_NAME == "client.client"
    logger = setup_logging(client_module.LOGGER_NAME, settings)
    assert logger.name == client_module.LOGGER_NAME
    assert logger.handlers


def test_server_entrypoint_logger_name_is_configured(settings: Settings) -> None:
    from server import server as server_module

    assert server_module.LOGGER_NAME == "server.server"
    logger = setup_logging(server_module.LOGGER_NAME, settings)
    assert logger.name == server_module.LOGGER_NAME
    assert logger.handlers


def test_setup_logging_writes_messages(settings: Settings) -> None:
    logger = setup_logging("tests.logging_probe", settings)
    logger.info("probe message")

    for handler in logger.handlers:
        handler.flush()
    log_file = settings.log_dir / "logging_probe.log"
    assert "probe message" in log_file.read_text(encoding="utf-8")
