"""
End-to-end threat intelligence pipeline.
Fetches recent CVEs, enriches them with KEV + EPSS + CVSS,
scores each with the prioritization engine, and prints a ranked feed.
"""

import requests
import csv
from prioritize import calculate_priority


def get_cvss_score(cve: dict) -> float:
    """Safely extract a CVSS base score from an NVD CVE record. Returns 0.0 if none found."""
    metrics = cve.get("metrics", {})
    # NVD stores CVSS under different keys by version; try v3.1, then v3.0, then v2.
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            return float(metrics[key][0]["cvssData"]["baseScore"])
    return 0.0


# --- 1. Fetch recent CVEs from NVD ---
print("Fetching recent CVEs from NVD...")
nvd_resp = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"resultsPerPage": 20, "startIndex": 371000},
)
cves = nvd_resp.json()["vulnerabilities"]
print("Total CVEs fetched:", len(cves))
print("Unique CVE IDs:    ", len(set(item["cve"]["id"] for item in cves)))

# --- 2. Fetch the KEV set (exploited CVE IDs) ---
print("Fetching CISA KEV catalog...")
kev_resp = requests.get(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
kev_ids = {v["cveID"] for v in kev_resp.json()["vulnerabilities"]}

# --- 3. Collect all CVE IDs, then fetch EPSS for ALL of them in ONE request ---
cve_ids = [item["cve"]["id"] for item in cves]
print("Fetching EPSS scores (one batched request)...")
epss_resp = requests.get(
    "https://api.first.org/data/v1/epss",
    params={"cve": ",".join(cve_ids)},
)
# Build a lookup: {cve_id: epss_score}
epss_scores = {e["cve"]: float(e["epss"]) for e in epss_resp.json()["data"]}

# --- 4. Score every CVE ---
results = []
for item in cves:
    cve = item["cve"]
    cve_id = cve["id"]

    on_kev = cve_id in kev_ids
    epss = epss_scores.get(cve_id, 0.0)   # 0.0 if EPSS has no score for it
    cvss = get_cvss_score(cve)

    priority = calculate_priority(on_kev=on_kev, epss=epss, cvss=cvss)
    results.append((priority, cve_id, on_kev, epss, cvss))

# --- 5. Sort by priority, highest first ---
results.sort(reverse=True)

# --- 6. Print the ranked feed ---
print("\n" + "=" * 70)
print("PRIORITIZED THREAT FEED  (patch top-down)")
print("=" * 70)
for priority, cve_id, on_kev, epss, cvss in results:
    kev_flag = "KEV" if on_kev else "   "
    print(f"{priority:5.1f}  {kev_flag}  {cve_id}  EPSS={epss:.3f}  CVSS={cvss:.1f}")
    
# --- 7. Save the ranked feed to a CSV file ---
output_file = "threats.csv"
with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    # Header row — names the columns
    writer.writerow(["priority", "cve_id", "on_kev", "epss", "cvss"])
    # One row per CVE, already sorted highest-priority first
    for priority, cve_id, on_kev, epss, cvss in results:
        writer.writerow([priority, cve_id, on_kev, epss, cvss])

print(f"\nSaved {len(results)} prioritized threats to {output_file}")