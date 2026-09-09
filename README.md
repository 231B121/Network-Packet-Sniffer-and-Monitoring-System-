# Network Packet Sniffer and Monitoring System

A Python-based network packet sniffer and monitoring system that captures
network packets in real time using Scapy.

The system analyzes Ethernet, IPv4, TCP, UDP, and ICMP headers and extracts
important information such as MAC addresses, IP addresses, port numbers,
packet size, protocol type, and TCP flags.

## Features

- Real-time packet capture
- Ethernet header analysis
- IPv4 header parsing
- TCP, UDP and ICMP detection
- TCP flag analysis
- Source and destination IP/port extraction
- Packet size monitoring
- Protocol distribution summary

## Technologies

- Python
- Scapy
- Struct

## How to Run

Install dependencies:

pip install -r requirements.txt

Run the packet sniffer:

python main.py

Administrator/root privileges may be required for live packet capture.