"""NVD CVE source client."""
import logging
from threatintel.config import settings
from threatintel.sources.base import BaseClient, SourceError

logger = logging.getLogger(__name__)


class NVDClient(BaseClient):
    """Fetches recent CVEs from the NVD 2.0 API."""

    def fetch_recent(self) -> list[dict]:
        params = {
            "resultsPerPage": settings.nvd_results_per_page,
            "startIndex": settings.nvd_start_index,
        }
        if settings.nvd_api_key:
            params["apiKey"] = settings.nvd_api_key

        data = self._get_json(settings.nvd_url, params=params)
        if "vulnerabilities" not in data:
            raise SourceError("NVD response missing 'vulnerabilities' key")

        cves = data["vulnerabilities"]
        logger.info("Fetched %d CVEs from NVD", len(cves))
        return cves