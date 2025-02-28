import scapy.all as scapy

def extract_pcap_metadata(packets):
    metadata = {
        "source_ips": set(),
        "destination_ips": set(),
        "protocols": set(),
        "user_agents": set(),
        "domains": set()
    }

    for packet in packets:
        if packet.haslayer(scapy.IP):
            metadata["source_ips"].add(packet[scapy.IP].src)
            metadata["destination_ips"].add(packet[scapy.IP].dst)

        for layer in packet.layers():
            protocol_name = layer.__name__
            metadata["protocols"].add(protocol_name)


        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load.decode(errors="ignore")
            if "User-Agent:" in payload:
                    try:
                        user_agent = payload.split("User-Agent: ")[1].split("\r\n")[0].strip()
                        metadata["user_agents"].add(user_agent)
                    except IndexError:
                        # Handle cases where the User-Agent header is malformed
                        user_agent = None

        if packet.haslayer(scapy.DNSQR):
            domain = packet[scapy.DNSQR].qname.decode()
            domain = domain.rstrip('.')
            metadata["domains"].add(domain)

    return metadata
