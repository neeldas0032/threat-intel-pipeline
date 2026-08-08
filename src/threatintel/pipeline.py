"""Orchestrates the threat-intel pipeline: fetch -> enrich -> score -> rank -> save."""
import csv
import logging

from threatintel.config import settings
from threatintel.scoring import calculate_priority
from threatintel.sources.nvd import NVDClient
from threatintel.sources.kev import KEVClient
from threatintel.sources.epss import EPSSClient
from threatintel.storage import save_results

logger = logging.getLogger(__name__)


def _get_cvss(cve: dict) -> float:
    """Extract a CVSS base score from an NVD CVE record; 0.0 if none present."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            return float(metrics[key][0]["cvssData"]["baseScore"])
    return 0.0


def run() -> list[tuple]:
    """Run the full pipeline and return ranked (priority, cve_id, on_kev, epss, cvss) tuples."""
    cves = NVDClient().fetch_recent()
    kev_ids = KEVClient().fetch_kev_ids()

    cve_ids = [item["cve"]["id"] for item in cves]
    epss_scores = EPSSClient().fetch_scores(cve_ids)

    results = []
    for item in cves:
        cve = item["cve"]
        cve_id = cve["id"]
        on_kev = cve_id in kev_ids
        epss = epss_scores.get(cve_id, 0.0)
        cvss = _get_cvss(cve)
        priority = calculate_priority(on_kev=on_kev, epss=epss, cvss=cvss)
        results.append((priority, cve_id, on_kev, epss, cvss))

    results.sort(reverse=True)
    logger.info("Scored and ranked %d CVEs", len(results))
    return results


def save_csv(results: list[tuple], path: str | None = None) -> None:
    """Write ranked results to CSV."""
    path = path or settings.output_csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["priority", "cve_id", "on_kev", "epss", "cvss"])
        writer.writerows(results)
    logger.info("Saved %d threats to %s", len(results), path)


def main() -> None:
    """Entry point: configure logging, run, print, and save."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    results = run()

    print("\n" + "=" * 70)
    print("PRIORITIZED THREAT FEED  (patch top-down)")
    print("=" * 70)
    for priority, cve_id, on_kev, epss, cvss in results:
        kev_flag = "KEV" if on_kev else "   "
        print(f"{priority:5.1f}  {kev_flag}  {cve_id}  EPSS={epss:.3f}  CVSS={cvss:.1f}")

    save_csv(results)
    save_results(results)

if __name__ == "__main__":
    main()