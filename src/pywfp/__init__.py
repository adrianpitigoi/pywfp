"""
PyWFP: A Python package for Windows Filtering Platform management
"""

import logging
import sys
from datetime import datetime
from typing import Optional


class ColorFormatter(logging.Formatter):
    """
    Custom formatter with colors
    """

    green = "\x1b[32m"
    yellow = "\x1b[33m"
    red = "\x1b[31m"
    bold_red = "\x1b[31;1m"
    blue = "\x1b[36m"
    reset = "\x1b[0m"

    COLORS = {
        logging.DEBUG: blue,
        logging.INFO: green,
        logging.WARNING: yellow,
        logging.ERROR: red,
        logging.CRITICAL: bold_red,
    }

    def formatTime(self, record, datefmt=None):
        # Create datetime object from timestamp
        dt = datetime.fromtimestamp(record.created)
        # Format with microseconds
        return dt.strftime("%Y-%m-%d %H:%M:%S.") + f"{dt.microsecond:06d}"

    def format(self, record: logging.LogRecord) -> str:
        # Call the parent class's format method first
        record.message = record.getMessage()

        # Add color to level name
        color = self.COLORS.get(record.levelno)
        record.levelname = f"{color}{record.levelname:<8}{self.reset}"

        # Format time
        record.asctime = self.formatTime(record)

        # Return formatted string matching loguru's pattern
        return f"{self.green}{record.asctime}{self.reset} | {record.levelname} | {record.name}:{record.lineno} - {record.message}"


def setup_logger(level=logging.INFO):
    """
    Setup the package logger with colored output.

    Args:
        level: The logging level to use (default: logging.INFO)
    """
    # Configure handler with custom formatter
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColorFormatter())

    # Configure package logger (not root logger)
    logger = logging.getLogger("pywfp")
    logger.setLevel(level)

    # Remove any existing handlers and add our handler
    logger.handlers.clear()
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False


# Create the logger but don't configure it by default
logger = logging.getLogger("pywfp")

from .core import PyWFP, WFPError
from .filter_parser import FilterParser
from .wfp_engine import WfpEngine
from .wfp_filter import WfpFilter

__version__ = "0.1.0"
__all__ = ["PyWFP", "WFPError", "FilterParser", "WfpEngine", "WfpFilter"]
