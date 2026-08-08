import requests

# --- 1. Fetch recent CVEs from NVD ---
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Ask for 20 recent CVEs, sorted so newest come first isn't offered,
# so we just grab a page starting further along to reach modern ones
nvd_params = {"resultsPerPage": 20, "startIndex": 371000}
nvd_response = requests.get(NVD_URL, params=nvd_params)
nvd_data = nvd_response.json()

# --- 2. Fetch the CISA KEV catalog ---
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
kev_response = requests.get(KEV_URL)
kev_data = kev_response.json()

# --- 3. Build a SET of exploited CVE IDs for instant lookup ---
# A set gives us near-instant "is this in here?" checks (O(1) time)
kev_ids = set()
for vuln in kev_data["vulnerabilities"]:
    kev_ids.add(vuln["cveID"])

print("Loaded", len(kev_ids), "exploited CVE IDs from KEV")
print("-" * 50)  # a divider line, just for readability

# --- 4. For each NVD CVE, check if it's on the KEV list ---
for item in nvd_data["vulnerabilities"]:
    cve = item["cve"]
    cve_id = cve["id"]

    if cve_id in kev_ids:
        status = "EXPLOITED"
    else:
        status = "not on KEV"

    print(cve_id, "->", status)
    print("-" * 50)
test_id = "CVE-2026-50522"
if test_id in kev_ids:
    print(test_id, "-> EXPLOITED (confirmed match!)")
else:
    print(test_id, "-> not found")