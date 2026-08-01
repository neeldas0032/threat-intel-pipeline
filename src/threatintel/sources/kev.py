"""CISA KEV source client."""
import logging
from threatintel.config import settings
from threatintel.sources.base import BaseClient, SourceError

logger = logging.getLogger(__name__)


class KEVClient(BaseClient):
    """Fetches the CISA Known Exploited Vulnerabilities catalog."""

    def fetch_kev_ids(self) -> set[str]:
        data = self._get_json(settings.kev_url)
        if "vulnerabilities" not in data:
            raise SourceError("KEV response missing 'vulnerabilities' key")

        kev_ids = {v["cveID"] for v in data["vulnerabilities"]}
        logger.info("Fetched %d exploited CVE IDs from KEV", len(kev_ids))
        return kev_ids