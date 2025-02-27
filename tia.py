import scapy.all as scapy
import requests
import pandas as pd
#from markdown_table import markdown_table
import argparse  

# Threat Intelligence Feeds 
THREAT_FEEDS = {
    "VirusTotal": "https://www.virustotal.com/api/v3/ip_addresses/"
}

# Replace with your API keys
API_KEYS = {
    "VirusTotal": "11951fc8ca67e60348eef508aa51102d25c6087e0d44ce11f600314060c04d73"
}

def extract_pcap_metadata(pcap_file):
    packets = scapy.rdpcap(pcap_file)
    metadata = {
        "source_ips": set(),
        "destination_ips": set(),
        "protocols": set(),
        "user_agents": set(),
        "files": set()
    }

    for packet in packets:
        if packet.haslayer(scapy.IP):
            metadata["source_ips"].add(packet[scapy.IP].src)
            metadata["destination_ips"].add(packet[scapy.IP].dst)

        if packet.haslayer(scapy.TCP):
            metadata["protocols"].add("TCP")
        elif packet.haslayer(scapy.UDP):
            metadata["protocols"].add("UDP")

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode(errors="ignore")
            if "User-Agent" in payload:
                user_agent = payload.split("User-Agent: ")[1].split("\r\n")[0]
                metadata["user_agents"].add(user_agent)

    return metadata

def query_threat_feeds(ip, feed_name):
    headers = {"Accept": "application/json"}
    if feed_name == "AbuseIPDB":
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        headers["Key"] = API_KEYS["AbuseIPDB"]
        response = requests.get(THREAT_FEEDS["AbuseIPDB"], headers=headers, params=params)
        return response.json()
    elif feed_name == "VirusTotal":
        headers["x-apikey"] = API_KEYS["VirusTotal"]
        response = requests.get(THREAT_FEEDS["VirusTotal"] + ip, headers=headers)
        return response.json()
    elif feed_name == "AlienVault OTX":
        response = requests.get(THREAT_FEEDS["AlienVault OTX"] + ip, headers=headers)
        return response.json()
    return None

def main(pcap_file):
    metadata = extract_pcap_metadata(pcap_file)
    print(metadata)

    threat_matches = {}
    for ip in metadata["source_ips"].union(metadata["destination_ips"]):
        matches = {}
        for feed in THREAT_FEEDS:
            result = query_threat_feeds(ip, feed)
            if result:
                matches[feed] = result
        if matches:
            threat_matches[ip] = matches

    #generate_report(metadata, threat_matches)

if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Threat Intelligence Automation Tool")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    args = parser.parse_args()

    # Run the main function with the provided PCAP file
    main(args.pcap_file)