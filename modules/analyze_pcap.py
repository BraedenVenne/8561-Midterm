from scapy.all import rdpcap, TCP, UDP, IP
from collections import defaultdict

# Parses packet capture files and checks for suspicious packet frequencies
def analyze_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print("ERROR|File not found on server")
        return "ERROR|File not found on server"
    
    results = []

    # Count all TCP packets in the packet capture file
    tcp_packets = [pkt for pkt in packets if TCP in pkt]
    results.append(f"TCP packets: {len(tcp_packets)}")

    # Count all UDP packets in  the packet capture file
    udp_packets = [pkt for pkt in packets if UDP in pkt]
    results.append(f"UDP packets: {len(udp_packets)}")

    # Create dictionary
    ip_timestamps = defaultdict(list)

    # Track suspicious IPs
    suspicious_ips = []

    # Process packets
    for pkt in packets:
        # Filter for IPv4 TCP or UDP traffic
        if IP in pkt and (TCP in pkt or UDP in pkt):
            src_ip = pkt[IP].src
            current_time = float(pkt.time)

            # Keep timestamps within 5 second window
            valid_timestamps = [t for t in ip_timestamps[src_ip] if t >= (current_time - 5.0)]

            # Record the current packet timestamp
            valid_timestamps.append(current_time)

            # Update the dictionary
            ip_timestamps[src_ip] = valid_timestamps

        # Trigger an alert if packet exceeds threshold 
        if len(ip_timestamps[src_ip]) > 20 and src_ip not in suspicious_ips:
            print(f"ALERT: Suspicious activity from {src_ip}")
            suspicious_ips.append(src_ip)

    # Format and append summary findings to output list
    results.append(f"Suspicious IPs Detected: {len(suspicious_ips)}")
    if suspicious_ips:
        count = 1
        for ip in suspicious_ips:
            results.append(f"   - Suspicious Target {count}: {ip}")
            count += 1
    else:
        results.append("No suspicious activity detected.")
                

    return "\n".join(results)
