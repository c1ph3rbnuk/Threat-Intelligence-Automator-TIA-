import pyshark
import hashlib
import requests
import json
import os
from datetime import datetime

# Threat Intelligence Feeds (Replace with API Keys if required)
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ALIENVAULT_OTX_API_KEY = "YOUR_ALIENVAULT_OTX_API_KEY"

def extract_metadata(pcap_file):
    """Extract metadata from the given PCAP file."""
    cap = pyshark.FileCapture(pcap_file)
    extracted_data = []
    
    for pkt in cap:
        try:
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else 'N/A'
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A'
            protocol = pkt.highest_layer
            user_agent = pkt.http.get('User-Agent', 'N/A') if hasattr(pkt, 'http') else 'N/A'
            
            extracted_data.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "user_agent": user_agent
            })
        except AttributeError:
            continue
    
    cap.close()
    return extracted_data

def check_threat_feeds(ip):
    """Check if an IP appears in threat intelligence feeds."""
    results = {}
    
    # AbuseIPDB Lookup
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        results['AbuseIPDB'] = response.json()
    
    # VirusTotal Lookup
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        results['VirusTotal'] = response.json()
    
    # AlienVault OTX Lookup
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": ALIENVAULT_OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        results['AlienVault'] = response.json()
    
    return results

def generate_report(metadata, threat_results, output_file="security_report.md"):
    """Generate a security report in Markdown format."""
    with open(output_file, "w") as report:
        report.write("# Security Analysis Report\n")
        report.write(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        report.write("## Findings\n")
        
        for data in metadata:
            report.write(f"- **Source IP:** {data['src_ip']}\n")
            report.write(f"  - Destination IP: {data['dst_ip']}\n")
            report.write(f"  - Protocol: {data['protocol']}\n")
            report.write(f"  - User-Agent: {data['user_agent']}\n\n")
        
        report.write("## Threat Intelligence Matches\n")
        for ip, results in threat_results.items():
            report.write(f"### IP: {ip}\n")
            for source, data in results.items():
                report.write(f"- **{source} Result:** {json.dumps(data, indent=2)}\n\n")
        
        report.write("## Recommendations\n")
        report.write("- Investigate any flagged IPs in your network logs.\n")
        report.write("- Apply necessary security patches if vulnerabilities are identified.\n")
    
    print(f"Report saved to {output_file}")

def main():
    pcap_file = "sample.pcap"  # Replace with actual file
    metadata = extract_metadata(pcap_file)
    
    # Check IPs against threat intelligence feeds
    threat_results = {}
    for entry in metadata:
        ip = entry['src_ip']
        if ip not in threat_results:
            threat_results[ip] = check_threat_feeds(ip)
    
    generate_report(metadata, threat_results)

if __name__ == "__main__":
    main()
