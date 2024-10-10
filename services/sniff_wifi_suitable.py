from scapy.all import sniff

def packet_handler(packet):
    print(packet.summary())

interfaces = [
    '{1586EE58-18DE-44A1-BE46-B6686F257F58}',
    '{036856A9-EE2C-4D1C-8582-4AF5B2A972FD}',
    '{7FCC5E41-9952-4292-B8E0-CD1ADCC4359B}',
    '{12D4E9A6-8593-4FF0-ACF7-9E843B3D7C12}',
    '{69277058-26E4-466F-9951-8F5C39C9B0CE}',
    '{315B1ACA-EA81-414D-B03F-15E53ECC715F}',
    '{A3788DEC-2F39-40BA-B2A4-B6F34902E561}',
    '{A43F5BB6-779E-4133-B623-E05824D605CE}'
]

for iface in interfaces:
    try:
        print(f"Trying interface: {iface}")
        sniff(prn=packet_handler, iface=iface, store=0, timeout=10)
    except Exception as e:
        print(f"Failed on interface {iface}: {e}")
