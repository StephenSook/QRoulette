"""Logging helpers for the application."""

import logging


class _DefaultContextFilter(logging.Filter):
    """Populate structured logging context fields when absent."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Ensure common context fields always exist for formatters."""

        if not hasattr(record, "scan_id"):
            record.scan_id = "-"
        return True


def configure_logging() -> None:
    """Configure process-wide logging once."""

    root_logger = logging.getLogger()
    if root_logger.handlers:
        return

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | scan_id=%(scan_id)s | %(message)s",
    )
    logging.getLogger().addFilter(_DefaultContextFilter())


def get_logger(name: str) -> logging.Logger:
    """Return a named application logger."""

    return logging.getLogger(name)
