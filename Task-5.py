import scapy.all as scapy


def sniff_packets(interface):
    print("[+] Sniffing started on interface:", interface)
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(
            f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            payload = packet[scapy.TCP].payload
            print("TCP Packet:")
            print(payload)
        elif packet.haslayer(scapy.UDP):
            payload = packet[scapy.UDP].payload
            print("UDP Packet:")
            print(payload)


# Usage example
interface = "eth0"  # Change this to your network interface
sniff_packets(interface)
