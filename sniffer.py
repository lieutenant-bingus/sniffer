from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys

def packet_callback(packet):
    """Process each captured packet."""
    # Check if it has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        # Identify protocol type
        if protocol == 6 and TCP in packet:  # TCP
            proto_name = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = bytes(packet[TCP].payload)[:20]  # First 20 bytes of payload
        elif protocol == 17 and UDP in packet:  # UDP
            proto_name = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = bytes(packet[UDP].payload)[:20]
        elif protocol == 1 and ICMP in packet:  # ICMP
            proto_name = "ICMP"
            src_port = dst_port = "N/A"
            payload = bytes(packet[ICMP].payload)[:20]
        else:
            proto_name = f"Other (Proto {protocol})"
            src_port = dst_port = "N/A"
            payload = b""
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load[:20].hex()
            print(f"Payload: {payload}")

        # Print packet summary
        print(f"[{proto_name}] {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        if payload:
            print(f"Payload (first 20 bytes): {payload.hex()}")

def start_sniffer(interface=None, count=10):
    """Start sniffing packets on the specified interface."""
    try:
        print(f"Sniffing on {interface if interface else 'default interface'}... Ctrl+C to stop.")
        # Sniff packets, call packet_callback for each, limit to 'count' packets
        sniff(iface=interface, prn=packet_callback, filter="tcp port 80 or tcp port 443", count=10)
    except PermissionError:
        print("Error: Run this script with sudo/admin privileges!")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Set interface (optional, leave None for default)
    interface = "Wi-Fi 3"  # e.g., "eth0" on Linux, "Wi-Fi" on Windows
    start_sniffer(interface=interface, count=10)  # Sniff 10 packets to start
