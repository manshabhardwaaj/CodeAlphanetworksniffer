# CodeAlphanetworksnifferimport scapy.all as scapy
pip install scapy
def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"IP Packet: {source_ip} --> {destination_ip} Protocol: {protocol}")
    elif packet.haslayer(scapy.ARP):
        source_ip = packet[scapy.ARP].psrc
        destination_ip = packet[scapy.ARP].pdst
        print(f"ARP Packet: {source_ip} --> {destination_ip}")

# Usage example
sniff_packets("eth0")  # Replace "eth0" with your network interface

