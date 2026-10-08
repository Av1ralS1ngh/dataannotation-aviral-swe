"""Small JSON logging setup used by HTTP service entry points."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from .config import get_settings


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        value = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in ("request_id", "repository", "channel", "decision_id"):
            if hasattr(record, field):
                value[field] = getattr(record, field)
        if record.exc_info:
            value["exception"] = self.formatException(record.exc_info)
        return json.dumps(value, sort_keys=True)


def configure_logging() -> None:
    root = logging.getLogger()
    if any(isinstance(handler.formatter, JsonFormatter) for handler in root.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(get_settings().log_level)
