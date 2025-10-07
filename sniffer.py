"""
Network Packet Sniffer using Scapy
Captures and displays IP, TCP, UDP, ICMP packets with payloads.
"""

from scapy.all import *
import datetime
import argparse

def packet_callback(packet):
    if packet.haslayer(IP):
        ip = packet.getlayer(IP)
        src_ip = ip.src
        dst_ip = ip.dst
        proto = ip.proto

        # Protocol mapping
        proto_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        proto_name = proto_names.get(proto, f'Unknown({proto})')

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {proto_name}: {src_ip} → {dst_ip}")

        # TCP
        if packet.haslayer(TCP):
            tcp = packet.getlayer(TCP)
            print(f"    📦 TCP {tcp.sport} → {tcp.dport} | Flags: {tcp.flags}")
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"    💬 Payload (hex): {payload.hex()}")
                print(f"    💬 Payload (text): {payload.decode('utf-8', errors='replace')}")

        # UDP
        elif packet.haslayer(UDP):
            udp = packet.getlayer(UDP)
            print(f"    📦 UDP {udp.sport} → {udp.dport}")
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"    💬 Payload (hex): {payload.hex()}")
                print(f"    💬 Payload (text): {payload.decode('utf-8', errors='replace')}")

        # ICMP
        elif packet.haslayer(ICMP):
            icmp = packet.getlayer(ICMP)
            print(f"    📦 ICMP Type: {icmp.type}, Code: {icmp.code}")
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                print(f"    💬 Payload (hex): {payload.hex()}")

        print("-" * 80)

def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("-f", "--filter", default="", help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    args = parser.parse_args()

    print("🚀 Starting Packet Capture...")
    if args.filter:
        print(f"🔧 Filter: '{args.filter}'")
    print("💡 Press Ctrl+C to stop.\n")

    try:
        sniff(
            prn=packet_callback,
            filter=args.filter,
            count=args.count,
            store=0
        )
    except PermissionError:
        print("❌ Error: Permission denied. Run with sudo (Linux/Mac) or as Admin (Windows).")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
