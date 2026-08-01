import requests

# CISA publishes the whole Known Exploited Vulnerabilities catalog as one JSON file
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Fetch the entire file — no parameters needed this time
response = requests.get(URL)
data = response.json()

# The list of exploited vulnerabilities lives under "vulnerabilities"
kev_list = data["vulnerabilities"]

# How many actively-exploited vulnerabilities does CISA currently track?
print("Total KEV entries:", len(kev_list))

# Print the first 5 so we can see the shape of the data
for vuln in kev_list[:5]:
    print(vuln["cveID"], "-", vuln["vulnerabilityName"])