import requests

# The NVD CVE API 2.0 endpoint — the "vending machine" URL
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Ask for just 5 results so we don't overwhelm ourselves
params = {"resultsPerPage": 5}

# Send the request and get the response back
response = requests.get(URL, params=params)

# Turn the JSON text into a Python dictionary
data = response.json()

# Print how many total CVEs exist in their database
print("Total CVEs in NVD:", data["totalResults"])

# Loop through the 5 we got back and print each one's ID
for item in data["vulnerabilities"]:
    cve = item["cve"]
    print(cve["id"])