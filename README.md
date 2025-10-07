
# Network Packet Sniffer

A simple Python program that captures and analyzes network traffic packets using the Scapy library.

## Features
- Captures live packets from your network interface
- Displays source/destination IPs, protocols (TCP/UDP/ICMP), ports, and payloads
- Helps understand how data flows across networks

## Requirements
- Python 3.x
- Scapy (`pip install scapy`)
- Admin/root privileges (to capture packets)

## Setup
bash pip install -r requirements.txt
##Usage

bash sudo python sniffer.py
> Note: Run with `sudo` on Linux/macOS for raw socket access.
## Example Output



## ⚠️ Legal Note
Only use this tool on networks you have permission to monitor. Unauthorized packet capturing may violate privacy laws.
