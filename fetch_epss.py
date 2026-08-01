import requests

# The EPSS API from FIRST.org
EPSS_URL = "https://api.first.org/data/v1/epss"

# We can ask about specific CVEs by passing their IDs, comma-separated
test_cves = "CVE-2021-44228"

params = {"cve": test_cves}
response = requests.get(EPSS_URL, params=params)
data = response.json()

# EPSS returns its results under the "data" key
print("EPSS returned", len(data["data"]), "results")
print("-" * 50)

for entry in data["data"]:
    cve_id = entry["cve"]
    # The score comes back as a string, so we convert it to a float (decimal number)
    score = float(entry["epss"])
    # Format it as a percentage with 2 decimal places for readability
    print(f"{cve_id} -> {score:.2%} chance of exploitation in next 30 days")