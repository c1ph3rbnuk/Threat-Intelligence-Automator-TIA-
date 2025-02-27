import scapy.all as scapy
import pandas as pd
from itertools import zip_longest
from detect import detect_malicious_requests
from preprocess import extract_pcap_metadata
from correlate import check_ip_reputation, check_domain_reputation, check_threatfox
import argparse
import json
import time
from py_markdown_table.markdown_table import markdown_table

THREAT_FEEDS = {
    "VirusTotal": "https://www.virustotal.com/api/v3/domain/",
    "AbuseIPDB": "https://api.abuseipdb.com/api/v2/check",
    "ThreatFox": "https://threatfox-api.abuse.ch/api/v1/"
}


def load_suspicious_patterns(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def generate_report(metadata, ip_matches, domain_matches):
    report = "# Security Analysis Report\n"

    report += "## Introduction\nThis report presents the findings of a comprehensive analysis of network traffic conducted using the Threat Intelligence Automation Tool. The tool is designed to analyze PCAP (Packet Capture) files, detect suspicious activity, and correlate findings with multiple threat intelligence feeds to identify potential security threats.\n"

    report += "## Scope and Objective\nThe scope of this analysis includes extracting key metadata from the network traffic, such as source and destination IP addresses, protocols, user-agent strings, and URLs. These fields are then compared against known threat intelligence feeds to identify malicious indicators of compromise (IOCs). The report also includes a detailed breakdown of detected threats, recommendations for remediation, and references to the threat intelligence feeds used.\n The primary objective is to detect any threats within the network capture and offer mitigation for the identified threats in order to improve the overal security of the network\n"

    report += "## Findings\n"
    report += "#### Network Metadata\n"

    # Transform metadata into a list of dictionaries
    metadata_table = [
        {
            "Source IPs": ", ".join(metadata.get("source_ips", [])),
            "Destination IPs": ", ".join(metadata.get("destination_ips", [])),
            "Protocols": ", ".join(metadata.get("protocols", [])),
            "User Agents": ", ".join(metadata.get("user_agents", []))
        }
    ]

    # Generate the report
    report += markdown_table(metadata_table).get_markdown() + "\n"

    report += "#### Threat Intelligence Matches\n"
    if ip_matches:
        report+= "The following IP addressed matched with threat intelligence feeds as shown\n"
        table_data = []
        for ip, details in ip_matches.items():
            table_data.append({
                "IP": ip,
                "Verdict": details["verdict"],
                "Feed": details["feed"],
                "Abuse Confidence Score": details["abuseConfidenceScore"]
            })
        report += markdown_table(table_data).get_markdown() + "\n"
    else:
        report+= "No Malicious Ips Identified!!!!\n"

    if domain_matches:
        report+= "The following Domain names matched with threat intelligence feeds as shown\n"
        domain_data = []
        for domain, details in domain_matches.items():
            domain_data.append({
                "Domain": domain,
                "Verdict": details["verdict"],
                "Feed": details["feed"],
                "Threat type": details["data"]["threat_type"]
            })
        report += markdown_table(domain_data).get_markdown() + "\n"
    else:
        report+= "No Malicious Domains Identified!!!!\n"

    report += "### Recommendations\nBased on the findings of this analysis, the following recommendations are provided to mitigate identified threats\n"
    report += "- Investigate suspicious IPs and user agents further.\n"
    report += "- Block malicious IPs identified in threat intelligence feeds.\n"

    report += "## References\n"
    report += "- AbuseIPDB\n- VirusTotal\n"

    report += "## Conclusion\nThis analysis highlights potential threats in the network traffic. Further investigation is recommended.\n"

    with open("security_report1.md", "w") as f:
        return f.write(report)


def main(pcap_file):
    print(f"[*] Loading detection patterns")
    suspicious_patterns = load_suspicious_patterns("suspicious-patterns.json")
    packets = scapy.rdpcap(pcap_file)

    print(f"[*] Extracting metadata from packet file")
    metadata = extract_pcap_metadata(packets)
    print(metadata, "\n")

    print(f"[*] Detecting malicious requests from the trace file")
    malicious = detect_malicious_requests(packets, suspicious_patterns)
    if malicious:
        print(malicious)
    else:
        print(f"No malicious request detected")

    ip_threat_matches = {}
    domain_threat_matches = {}

    print(f"[*] Checking Ips against AbuseIP intelligence database")
    for ip in metadata["source_ips"].union(metadata["destination_ips"]):
        result = check_ip_reputation(ip, THREAT_FEEDS["AbuseIPDB"])
        if result:
            if result["data"]["abuseConfidenceScore"] > 0:
                ip_threat_matches[ip] = {"verdict":"Malicious", "feed":"AbuseIPBD", "abuseConfidenceScore":result["data"]["abuseConfidenceScore"]}

    if ip_threat_matches:
        print(ip_threat_matches)
    else:
        print(f"No Ips match identified")

    print(f"[*] Checking domains against ThreatFox intelligence feed")
    domain_threat_matches = {}
    for d in metadata["domains"]:
        result = check_threatfox(THREAT_FEEDS["ThreatFox"], d)
        if result["query_status"] == "ok":
            domain_threat_matches[d] = {"verdict":"Malicious", "feed":"ThreatFox", "threat_type":result["data"]["threat_type"]}

    if domain_threat_matches:
        print(domain_threat_matches)
    else:
        print(f"No domain match identified")

    print(f"[*] Generating security analysis report")
    generate_report(metadata, ip_threat_matches, domain_threat_matches)
    print(f"security_report.md has been generated ")


if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Threat Intelligence Automation Tool")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    args = parser.parse_args()

    # Run the main function with the provided PCAP file
    main(args.pcap_file)