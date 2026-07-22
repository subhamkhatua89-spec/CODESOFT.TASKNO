from scapy.all import sniff, wrpcap, IP, TCP, UDP, Raw, ICMP
import datetime
import os
import sys

# List to store captured packets
captured_packets = []
packet_count = 0

def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Extracts and displays relevant network information.
    """
    global packet_count, captured_packets
    
    packet_count += 1
    captured_packets.append(packet)
    
    print(f"\n{'='*50}")
    print(f"Packet #{packet_count} Captured")
    print(f"{'='*50}")
    print(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}")
    
    # Inspect IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"\n[IP Layer]")
        print(f"  Source IP:      {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  TTL:            {ip_layer.ttl}")
        print(f"  Protocol:       {ip_layer.proto}")
        
        # Protocol mapping
        protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        protocol_name = protocol_map.get(ip_layer.proto, "Other")
        print(f"  Protocol Name:  {protocol_name}")
    
    # Inspect ICMP layer
    if ICMP in packet:
        icmp_layer = packet[ICMP]
        print(f"\n[ICMP Layer]")
        print(f"  Type: {icmp_layer.type}")
        print(f"  Code: {icmp_layer.code}")
    
    # Inspect TCP layer
    if TCP in packet:
        tcp_layer = packet[TCP]
        print(f"\n[TCP Layer]")
        print(f"  Source Port:      {tcp_layer.sport}")
        print(f"  Destination Port: {tcp_layer.dport}")
        print(f"  Flags:            {tcp_layer.flags}")
        print(f"  Sequence Number:  {tcp_layer.seq}")
        print(f"  Acknowledgment:   {tcp_layer.ack}")
    
    # Inspect UDP layer
    elif UDP in packet:
        udp_layer = packet[UDP]
        print(f"\n[UDP Layer]")
        print(f"  Source Port:      {udp_layer.sport}")
        print(f"  Destination Port: {udp_layer.dport}")
        print(f"  Length:           {udp_layer.len}")
    
    # Inspect raw payload
    if packet.haslayer(Raw):
        raw_data = packet[Raw].load
        print(f"\n[Payload]")
        print(f"  Data (first 50 bytes): {raw_data[:50]}")
        print(f"  Total Size: {len(raw_data)} bytes")
    
    print(f"{'='*50}")


def main():
    """Main function to start packet capture."""
    print("\n" + "="*50)
    print("PACKET SNIFFER - Network Packet Capture Tool")
    print("="*50)
    print(f"\nStarting packet capture...")
    print("Press Ctrl+C to stop and save packets.\n")
    
    try:
        # Start sniffing packets (store=False to save memory)
        sniff(prn=packet_callback, store=False)
    
    except KeyboardInterrupt:
        print("\n\n" + "="*50)
        print("CAPTURE STOPPED")
        print("="*50)
        
        # Save packets to a .pcap file
        if captured_packets:
            filename = f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            output_path = os.path.join(os.getcwd(), filename)
            
            try:
                wrpcap(output_path, captured_packets)
                print(f"\n✓ Total packets captured: {packet_count}")
                print(f"✓ Packets saved to: {output_path}")
                print(f"✓ File size: {os.path.getsize(output_path)} bytes")
            except Exception as e:
                print(f"\n✗ Error saving packets: {str(e)}")
        else:
            print("\nNo packets were captured.")
        
        print("="*50 + "\n")


if __name__ == "__main__":
    # Check for root privileges (required for packet sniffing)
    if os.geteuid() != 0 and sys.platform != "win32":
        print("\n⚠ Warning: This script requires root/administrator privileges to capture packets.")
        print("Please run with: sudo python3 Packet_sniffer.py\n")
        sys.exit(1)
    
    main()
