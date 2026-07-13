from scapy.all import sniff, wrpcap, IP, TCP, UDP, Raw
import datetime

# List to store captured packets
captured_packets = []

def packet_callback(packet):
    captured_packets.append(packet)

    print("\n=== Packet Captured ===")
    print(f"Timestamp: {datetime.datetime.now()}")

    # Inspect IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

    # Inspect TCP/UDP layers
    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"TCP Source Port: {tcp_layer.sport}")
        print(f"TCP Destination Port: {tcp_layer.dport}")
    elif UDP in packet:
        udp_layer = packet[UDP]
        print(f"UDP Source Port: {udp_layer.sport}")
        print(f"UDP Destination Port: {udp_layer.dport}")

    # Inspect raw payload
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        print(f"Packet Data (first 50 bytes): {raw_data[:50]}")

print("Starting packet capture... Press Ctrl+C to stop.")

try:
    sniff(prn=packet_callback, store=False)
except KeyboardInterrupt:
    # Save packets to a .pcap file when stopped
    filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    wrpcap(filename, captured_packets)
    print(f"\nCapture stopped. Packets saved to {filename}")
