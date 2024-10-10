# from scapy.all import sniff
# import socket

# def packet_handler(packet):
#     if packet.haslayer('Ether'):
#         # Print the source and destination MAC addresses
#         print(f"Source MAC: {packet['Ether'].src}")
#         print(f"Destination MAC: {packet['Ether'].dst}")
        
#         # Check if the packet has an IP layer
#         if packet.haslayer('IP'):
#             src_ip = packet['IP'].src
#             try:
#                 # Perform reverse DNS lookup for the source IP
#                 src_name = socket.gethostbyaddr(src_ip)[0]
#                 print(f"Source Device Name: {src_name}")
#             except socket.herror:
#                 print(f"Source Device Name: Not Found")
                
#             dst_ip = packet['IP'].dst
#             try:
#                 # Perform reverse DNS lookup for the destination IP
#                 dst_name = socket.gethostbyaddr(dst_ip)[0]
#                 print(f"Destination Device Name: {dst_name}")
#             except socket.herror:
#                 print(f"Destination Device Name: Not Found")

# sniff(prn=packet_handler, iface="Wi-Fi 2", store=0)

# from scapy.all import sniff

# def packet_handler(packet):
#     # Check if the packet has an IP layer (IPv4 or IPv6)
#     if packet.haslayer('IP'):
#         # Extract source and destination IPv4 addresses
#         print(f"Source IP: {packet['IP'].src}")
#         print(f"Destination IP: {packet['IP'].dst}")
#     elif packet.haslayer('IPv6'):
#         # Extract source and destination IPv6 addresses
#         print(f"Source IPv6: {packet['IPv6'].src}")
#         print(f"Destination IPv6: {packet['IPv6'].dst}")

# sniff(prn=packet_handler, iface="Wi-Fi 2", store=0)
# -----------------------------------------------------------------------------------------------------------------------------------------------
from scapy.all import sniff
from collections import defaultdict

# Dictionary to track unique MAC addresses and their device count
devices = defaultdict(bool)

def packet_handler(packet):
    # Check if the packet has an Ethernet (MAC) layer
    if packet.haslayer('Ether'):
        # Get the source MAC address
        src_mac = packet['Ether'].src
        
        # If the MAC address is new, mark it as connected
        if not devices[src_mac]:
            devices[src_mac] = True
            print(f"New device detected: {src_mac}")
            print(f"Total connected devices: {len(devices)}")
    
        # Optional: Print MAC address only if it's a destination packet (other connected devices)
        dst_mac = packet['Ether'].dst
        if not devices[dst_mac]:
            devices[dst_mac] = True
            print(f"New device detected: {dst_mac}")
            print(f"Total connected devices: {len(devices)}")

# Sniffing the Wi-Fi interface
sniff(prn=packet_handler, iface="Wi-Fi 2", store=0)
# --------------------------------------------------------------------------------------------------------------------------------------------------
# from scapy.all import sniff
# from collections import defaultdict
# from scapy.layers.dot11 import Dot11

# # Dictionary to track unique MAC addresses
# devices = defaultdict(bool)

# def packet_handler(packet):
#     # Check if the packet has an 802.11 layer (Wi-Fi) and is a probe request
#     if packet.haslayer(Dot11) and packet.type == 0 and packet.subtype == 4:  # subtype 4 is Probe Request
#         # Get the source MAC address (the device sending the probe request)
#         src_mac = packet['Dot11'].addr2
        
#         # If the MAC address is new, mark it as seen
#         if not devices[src_mac]:
#             devices[src_mac] = True
#             print(f"Device detected in range: {src_mac}")
#             print(f"Total devices detected: {len(devices)}")

# # Sniffing the Wi-Fi interface
# sniff(prn=packet_handler, iface="Wi-Fi 2", store=0)


