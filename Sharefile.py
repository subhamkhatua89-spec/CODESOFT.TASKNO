from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from datetime import datetime


def packet_callback(packet):
    print("=" * 80)

    # Timestamp
    print("Time :", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # ARP Packet
    if packet.haslayer(ARP):
        arp = packet[ARP]
        print("Protocol      : ARP")
        print("Source MAC    :", arp.hwsrc)
        print("Destination MAC:", arp.hwdst)
        print("Source IP     :", arp.psrc)
        print("Destination IP:", arp.pdst)
        return

    # IP Packet
    if packet.haslayer(IP):
        ip = packet[IP]

        print("Source IP      :", ip.src)
        print("Destination IP :", ip.dst)

        # TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol       : TCP")
            print("Source Port    :", tcp.sport)
            print("Destination Port:", tcp.dport)

        # UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol       : UDP")
            print("Source Port    :", udp.sport)
            print("Destination Port:", udp.dport)

        # ICMP
        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print("Protocol       :", ip.proto)

        print("Packet Length  :", len(packet))

        # Payload
        raw_bytes = bytes(packet)

        print("\nPacket Data (First 64 Bytes)")
        print(raw_bytes[:64].hex())

    else:
        print("Non-IP Packet")
        print(packet.summary())


print("Starting Packet Capture...")
print("Press CTRL+C to stop.\n")

sniff(prn=packet_callback, store=False)