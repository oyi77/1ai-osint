"""Structured JSON logging configuration for production use."""

import json
import logging
import os
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc)
        payload: dict = {
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Attach any extra fields the caller passed via logging.info("msg", extra={...})
        reserved = logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
        for key, value in record.__dict__.items():
            if key not in reserved and key not in ("message", "msg", "args"):
                payload[key] = value
        if record.exc_info and record.exc_info[1] is not None:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


_HUMAN_FMT = "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"


def setup_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Configure the root logger.

    Parameters
    ----------
    level : str
        Minimum log level. Overridden by the ``LOG_LEVEL`` env-var when set.
    json_format : bool
        Use ``JSONFormatter`` when *True*, human-readable text when *False*.
        Overridden by the ``LOG_FORMAT`` env-var when set (``json`` → True).

    """
    env_level = os.environ.get("LOG_LEVEL")
    if env_level:
        level = env_level

    env_fmt = os.environ.get("LOG_FORMAT")
    if env_fmt is not None:
        json_format = env_fmt.lower() == "json"

    numeric = getattr(logging, level.upper(), logging.INFO)

    handler = logging.StreamHandler(sys.stderr)
    if json_format:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(_HUMAN_FMT, datefmt="%Y-%m-%d %H:%M:%S"))

    root = logging.getLogger()
    root.setLevel(numeric)
    # Remove any pre-existing handlers so repeated calls don't stack.
    root.handlers.clear()
    root.addHandler(handler)
