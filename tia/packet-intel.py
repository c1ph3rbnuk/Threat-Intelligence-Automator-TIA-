import scapy.all as scapy
import pandas as pd
from detect import detect_malicious_requests
from preprocess import extract_pcap_metadata
from correlate import check_ip_reputation, check_domain_reputation
import argparse
import json
import time
from py_markdown_table import markdown_table

THREAT_FEEDS = {
    "VirusTotal": "https://www.virustotal.com/api/v3/ip_addresses/",
    "AbuseIPDB": "https://api.abuseipdb.com/api/v2/check"
}


def load_suspicious_patterns(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def main(pcap_file):
    suspicious_patterns = load_suspicious_patterns("suspicious-patterns.json")
    packets = scapy.rdpcap(pcap_file)

    metadata = extract_pcap_metadata(packets)
    print(metadata, "\n")

    malicious = detect_malicious_requests(packets, suspicious_patterns)
    print(malicious, "\n")

    ip_threat_matches = {}
    domain_threat_matches = {}

    for ip in metadata["source_ips"].union(metadata["destination_ips"]):
        matches = {}
        result = check_ip_reputation(ip, THREAT_FEEDS["AbuseIPDB"])
        if result:
            matches[feed] = result
        if matches:
            ip_threat_matches[ip] = matches

    print(ip_threat_matches)

    domain_threat_matches = {}
    for d in metadata["domains"]:
        matches = {}
        result = check_domain_reputation(THREAT_FEEDS["VirusTotal"], api)
        if result:
            matches[feed] = result
        if matches:
            domain_threat_matches[d] = matches

    print(domain_threat_matches)

    return ip_threat_matches, domain_threat_matches

def generate_report(metadata, ip_threat_matches, domain_threat_matches):
    report = "# Security Analysis Report\n\n"
    report += "## Introduction\nThis report summarizes the findings from the PCAP analysis and threat intelligence correlation.\n\n"
    report += "## Scope and Objective\nAnalyze network traffic for suspicious activity and correlate findings with threat intelligence feeds.\n\n"

    report += "## Findings\n"
    report += "### Network Metadata\n"
    metadata_table = {
        "Source IPs": list(metadata["source_ips"]),
        "Destination IPs": list(metadata["destination_ips"]),
        "Protocols": list(metadata["protocols"]),
        "User Agents": list(metadata["user_agents"])
    }
    report += markdown_table(pd.DataFrame(metadata_table)).to_markdown(index=False) + "\n\n"

    report += "### Threat Intelligence Matches\n"
    threat_table = []
    for ip, matches in threat_matches.items():
        for feed, result in matches.items():
            threat_table.append({"IP": ip, "Feed": feed, "Result": str(result)})
    report += markdown_table(pd.DataFrame(threat_table)).to_markdown(index=False) + "\n\n"

    report += "## Recommendations\n"
    report += "- Investigate suspicious IPs and user agents further.\n"
    report += "- Block malicious IPs identified in threat intelligence feeds.\n\n"

    report += "## References\n"
    report += "- AbuseIPDB\n- VirusTotal\n- AlienVault OTX\n\n"

    report += "## Conclusion\nThis analysis highlights potential threats in the network traffic. Further investigation is recommended.\n"

    with open("security_report.md", "w") as f:
        f.write(report)

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Threat Intelligence Automation Tool")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    args = parser.parse_args()

    # Run the main function with the provided PCAP file
    main(args.pcap_file)