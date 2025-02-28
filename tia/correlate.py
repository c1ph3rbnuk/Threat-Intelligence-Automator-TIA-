import requests
API_KEYS = {
    "VirusTotal": "11951fc8ca67e60348eef508aa51102d25c6087e0d44ce11f600314060c04d73",
    "AbuseIPDB": "184a06312a24a89550112cdae5e3bbdb81276569f71335094ecf73250478281a620be3e58505900e",
    "ThreatFox": "136248ce3305f88bf0166f6a7c830067b00ccc73cbcff224"
}

def check_ip_reputation(ip, api):
    results = {}

    # AbuseIPDB Lookup
    querystring = {'ipAddress': ip,'maxAgeInDays': '90'}
    headers = {"Key": API_KEYS["AbuseIPDB"], "Accept": "application/json"}
    response = requests.get(url=api, headers=headers, params=querystring)
    if response.status_code == 200:
        results = response.json()

    return results

def check_domain_reputation(domain, api):
    results = {}

    # VirusTotal domain Lookup
    v_api = f"{api}{domain}"
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

def check_threatfox(api, domain, exact_match=True):
    headers = {
        "Auth-Key": API_KEYS["ThreatFox"],
        "Content-Type": "application/json"
    }

    payload = {
        "query": "search_ioc",
        "search_term": domain,
        "exact_match": exact_match
    }

    try:
        response = requests.post(api, headers=headers, json=payload)

        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"API request failed with status code {response.status_code}",
                "details": response.text
            }
    except Exception as e:
        return {
            "error": f"An error occurred: {str(e)}"
        }