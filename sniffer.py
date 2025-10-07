
from scapy.all import *
import time

def packet_callback(packet):
    """
    Callback function to analyze and display packet information.
    """
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Determine protocol name
        proto_name = "Unknown"
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"

        print(f"\n[+] Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"    Source IP: {src_ip}")
        print(f"    Destination IP: {dst_ip}")
        print(f"    Protocol: {proto_name} (Protocol Number: {protocol})")

        # Check for TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"    Source Port: {tcp_layer.sport}")
            print(f"    Destination Port: {tcp_layer.dport}")
            print(f"    Flags: {tcp_layer.flags}")

            # Check for payload in TCP
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"    Payload (Raw Data): {payload.hex()}")

        # Check for UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"    Source Port: {udp_layer.sport}")
            print(f"    Destination Port: {udp_layer.dport}")

            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"    Payload (Raw Data): {payload.hex()}")

        # Check for ICMP layer
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"    ICMP Type: {icmp_layer.type}, Code: {icmp_layer.code}")
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"    Payload (Raw Data): {payload.hex()}")

        # Print a separator
        print("-" * 80)

def start_sniffer(interface=None, count=0):
    """
    Start packet sniffing.
    
    :param interface: Network interface to sniff on (e.g., 'eth0', 'wlan0'). Use None for default.
    :param count: Number of packets to capture (0 = infinite).
    """
    print("Starting packet sniffer... (Press Ctrl+C to stop)")
    print("Listening on interface:", interface or "default")
    print("-" * 80)

    try:
        # Start sniffing
        sniff(iface=interface, prn=packet_callback, count=count, store=False)
    except KeyboardInterrupt:
        print("\n[!] Packet sniffing stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    # Optional: List available interfaces
    print("Available interfaces:")
    print(get_if_list())
    print()

    # Choose interface (you can change this)
    interface_name = input("Enter interface to sniff on (or press Enter for default): ").strip()
    if not interface_name:
        interface_name = None

    # Start the sniffer
    start_sniffer(interface=interface_name, count=0)
