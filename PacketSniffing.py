from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

# Function to handle each captured packet
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto  # 6=TCP, 17=UDP

        # Initialize port variables
        src_port = dst_port = 'N/A'

        # Determine protocol and extract ports if possible
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol_name = "UDP"
        else:
            protocol_name = f"Other (Protocol Num: {protocol})"

        # Extract payload (if available)
        if packet.haslayer(Raw):
            payload = packet[Raw].load[:100]  # Limit to first 100 bytes
        else:
            payload = b''

        # Timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Display packet info
        print(f"\n[+] Packet Captured at {timestamp}")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {protocol_name}")
        print(f"    Source Port    : {src_port}")
        print(f"    Destination Port: {dst_port}")
        print(f"    Payload (raw)  : {payload}")

# Entry point for the script
def main():
    print("🔍 Starting network sniffer... Press Ctrl+C to stop.")
    sniff(filter="ip", prn=process_packet, store=0)

if __name__ == "__main__":
    main()
