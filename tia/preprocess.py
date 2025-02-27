import scapy.all as scapy

def extract_pcap_metadata(packets):
    print(f"-------------EXTRACTING METADATA------------")
    metadata = {
        "source_ips": set(),
        "destination_ips": set(),
        "protocols": set(),
        "user_agents": set(),
        "urls": set(),
        "domains": set()
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
            if "User-Agent:" in payload:
                    try:
                        user_agent = payload.split("User-Agent: ")[1].split("\r\n")[0].strip()
                        metadata["user_agents"] = user_agent
                    except IndexError:
                        # Handle cases where the User-Agent header is malformed
                        user_agent = None

            '''if "HTTP" in payload:
                # Extract the request line (e.g., "GET /index.html HTTP/1.1")
                request_line = payload.split("\r\n")[0]
                if request_line[0].startswith(("GET", "POST", "PUT", "DELETE", "HEAD")):
                    method, path, _ = request_line.split(" ")

                    # Extract the Host header (if present)
                    host = None
                    if "Host:" in payload:
                        try:
                            host = payload.split("Host: ")[1].split("\r\n")[0].strip()
                        except IndexError:
                            # Handle cases where the Host header is malformed
                            host = None

                    # Construct the full URL
                    if host and path:
                        url = f"http://{host}{path}"
                        metadata["urls"].add(url)'''

        if packet.haslayer(scapy.DNSQR):
            domain = packet[scapy.DNSQR].qname.decode()
            domain = domain.rstrip('.')
            metadata["domains"].add(domain)

    print(f"----------------METADATA EXTRACTION COMPLETE--------------------")
    return metadata
