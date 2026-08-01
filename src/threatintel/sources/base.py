"""Shared HTTP base for source clients."""
import logging
import requests
from threatintel.config import settings

logger = logging.getLogger(__name__)


class SourceError(Exception):
    """Raised when a data source cannot be fetched or returns unexpected data."""


class BaseClient:
    """Common HTTP GET with timeout, status check, and JSON parsing."""

    def _get_json(self, url: str, params: dict | None = None) -> dict:
        try:
            resp = requests.get(url, params=params, timeout=settings.request_timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as exc:
            logger.error("Request to %s failed: %s", url, exc)
            raise SourceError(f"Failed to fetch {url}") from exc
        except ValueError as exc:  # JSON decode error
            logger.error("Invalid JSON from %s: %s", url, exc)
            raise SourceError(f"Invalid JSON from {url}") from exc