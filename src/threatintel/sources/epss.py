"""EPSS source client (batched)."""
import logging
from threatintel.config import settings
from threatintel.sources.base import BaseClient, SourceError

logger = logging.getLogger(__name__)


class EPSSClient(BaseClient):
    """Fetches exploitation probabilities from FIRST EPSS in one batched request."""

    def fetch_scores(self, cve_ids: list[str]) -> dict[str, float]:
        if not cve_ids:
            return {}

        params = {"cve": ",".join(cve_ids)}
        data = self._get_json(settings.epss_url, params=params)
        if "data" not in data:
            raise SourceError("EPSS response missing 'data' key")

        scores = {e["cve"]: float(e["epss"]) for e in data["data"]}
        logger.info("Fetched %d EPSS scores", len(scores))
        return scores