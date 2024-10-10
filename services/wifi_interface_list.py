from scapy.all import get_if_list
from scapy.all import get_if_hwaddr

# print(get_if_list())

# Print all interfaces with their MAC addresses
for iface in get_if_list():
    try:
        print(f"{iface}: {get_if_hwaddr(iface)}")
    except:
        # Some interfaces may not have a MAC address, so we skip those
        pass