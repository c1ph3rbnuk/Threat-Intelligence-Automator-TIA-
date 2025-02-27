import pyshark
import argparse  
import hashlib
import requests
import json
import os
from datetime import datetime

THREAT_FEEDS = {
    "VirusTotal": "https://www.virustotal.com/api/v3/ip_addresses/"
}

# Threat Intelligence Feeds (Replace with API Keys if required)
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
VIRUSTOTAL_API_KEY = "11951fc8ca67e60348eef508aa51102d25c6087e0d44ce11f600314060c04d73"

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

def main(pcap_file):
    metadata = extract_metadata(pcap_file)
    print(metadata)

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Threat Intelligence Automation Tool")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    args = parser.parse_args()

    # Run the main function with the provided PCAP file
    main(args.pcap_file)