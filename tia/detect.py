import scapy.all as scapy

def detect_malicious_requests(packets, suspicious_patterns):
    print(f"-------------------DETECTING MALICIOUS REQUESTS-------------------------")
    malicious_requests = []

    for packet in packets:
        if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode(errors="ignore")

            # Check for HTTP requests
            if "HTTP" in payload:
                # Extract the request line (e.g., "GET /index.html HTTP/1.1")
                request_line = payload.split("\r\n")[0]
                if request_line[0].startswith(("GET", "POST", "PUT", "DELETE", "HEAD")):
                    method, path, _ = request_line.split(" ")

                    # Check for suspicious methods
                    if method in suspicious_patterns["suspicious_methods"]:
                        malicious_requests.append({
                            "type": "Suspicious HTTP Method",
                            "request": http_request,
                            "source_ip": packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
                        })

                    # Check for suspicious uris
                    if any(suspicious in path for suspicious in suspicious_patterns["suspicious_uris"]):
                        malicious_requests.append({
                            "type": "Suspicious uri",
                            "request": http_request,
                            "source_ip": packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
                        })

            # Check for suspicious user agents
            if "User-Agent:" in payload:
                user_agent = payload.split("User-Agent: ")[1].split("\r\n")[0]
                if any(suspicious in user_agent.lower() for suspicious in suspicious_patterns["suspicious_user_agents"]):
                    malicious_requests.append({
                        "type": "Suspicious User-Agent",
                        "user-agent": user_agent,
                        "source_ip": packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
                    })

    print(f"-------------------DETECTION COMPLETE----------------------")

    return malicious_requests
