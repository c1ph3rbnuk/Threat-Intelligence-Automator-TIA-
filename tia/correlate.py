import requests

API_KEYS = {
    "VirusTotal": "xxxxxxxxxxxxxxxxxxxxxxx",
    "AbuseIPDB": "xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

}

def check_ip_reputation(ip, api):
    """Check if an IP appears in threat intelligence feeds."""

    results = {}

    # AbuseIPDB Lookup
    querystring = {'ipAddress': ip,'maxAgeInDays': '90'}
    headers = {"Key": API_KEYS["AbuseIPDB"], "Accept": "application/json"}
    response = requests.get(url=api, headers=headers, params=querystring)
    if response.status_code == 200:
        ab_results = response.json()
        if ab_results["data"]["totalReports"] > 0:
            # Extract the required fields
            abused = {
                "ipAddress": data["data"]["ipAddress"],
                "countryCode": data["data"]["countryCode"],
                "abuseConfidenceScore": data["data"]["abuseConfidenceScore"],
                "lastReportedAt": data["data"]["lastReportedAt"]
            }

            results['AbuseIPDB'] = abused.json()

    return results

def check_domain_reputation(domain, api):
    """Check if an IP appears in threat intelligence feeds."""

    results = {}

    # VirusTotal domain Lookup
    v_api = f"{api}{ip}"
    headers = {"x-apikey": API_KEYS["VirusTotal"]}
    response = requests.get(v_api, headers=headers)
    if response.status_code == 200:
        vt_results = response.json()

        if vt_results["data"]["attributes"]["last_analysis_stats"]["malicious"] >= 1:
            vt = {
            "domain": data["data"]["id"],
            "malicious": data["data"]["attributes"]["last_analysis_stats"]["malicious"],
            "last_analysis_date": data["data"]["attributes"]["last_analysis_date"],
            "reputation": data["data"]["attributes"]["reputation"]
            }

            results["VirusTotal"] = vt.json()

    return results