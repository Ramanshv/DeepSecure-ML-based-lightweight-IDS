"""
src/logger.py - Shared logging configuration for DeepSecure IDS.

Usage:
    from src.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Model loaded successfully.")
"""

import logging
import sys
from pathlib import Path

LOG_DIR = Path(__file__).parent.parent / "outputs" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Return a named logger configured with console + rotating file handlers."""
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers when module is imported multiple times
    if logger.handlers:
        return logger

    logger.setLevel(level)

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)-8s] %(name)s – %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── Console (stdout) ──────────────────────────────────────
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # ── File (daily rotation) ─────────────────────────────────
    from logging.handlers import TimedRotatingFileHandler
    fh = TimedRotatingFileHandler(
        LOG_DIR / "ids.log",
        when="midnight",
        backupCount=7,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Don't propagate to root logger to avoid double-printing
    logger.propagate = False

    return logger
