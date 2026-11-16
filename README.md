# 📡 Network Packet Sniffer & Traffic Flow Observatory
### Real-Time Network Packet Inspection, Entity Resolution & Bandwidth Monitoring

A clean, modern, student-built network packet sniffer and monitoring observatory engineered in **Python**, **Scapy**, and **Flask**.

This tool captures network traffic passing through your computer's network interface (Wi-Fi, Ethernet, or Loopback), identifies **where packets originate and where they are destined in human-readable terms** (e.g., `Google Chrome (Local Host) ➔ Google Services` or `Cloudflare DNS Resolver ➔ Local Host`), categorizes traffic direction (**Upload ⬆ vs Download ⬇**), and presents it in a clean, high-contrast, professional **Light Dashboard**.

---

## 📑 Table of Contents

1. [Real-World Entity Resolution Engine](#-real-world-entity-resolution-engine)
2. [Key Features](#-key-features)
3. [System Architecture & File Structure](#-system-architecture--file-structure)
4. [Installation & Prerequisites](#-installation--prerequisites)
5. [How to Run: Web Dashboard](#-how-to-run-web-dashboard)
6. [How to Run: CLI Terminal Mode](#-how-to-run-cli-terminal-mode)
7. [Dashboard Interface Walkthrough](#-dashboard-interface-walkthrough)
8. [Theoretical Networking Guide (Viva / Presentation)](#-theoretical-networking-guide-viva--presentation)
9. [Troubleshooting & Frequently Asked Questions](#-troubleshooting--frequently-asked-questions)

---

## 🔍 Real-World Entity Resolution Engine

Traditional packet sniffers display confusing numerical representations, such as `192.168.1.15:52310 -> 142.250.190.46:443`. For students and educators, determining which local application or remote service is communicating can be challenging.

This project implements an **Entity Resolution Engine** that labels every packet with clear contextual information:
1. **Source Entity (Origin):** e.g., `Google Chrome (Local Host)`, `Mozilla Firefox (Local Host)`, `VS Code`, or `Cloudflare DNS Resolver (1.1.1.1)`.
2. **Destination Entity (Target):** e.g., `Google Web Services (HTTPS)`, `Wi-Fi Router Gateway (192.168.1.1)`, `GitHub Cloud`, `Spotify Media CDN`.
3. **Traffic Direction Detection (Flow):**
   - **Upload ⬆ (Outbound):** When your computer initiates or sends data to external internet servers.
   - **Download ⬇ (Inbound):** When an external server sends data or responses back to your computer.
   - **Local LAN 🔄 (Internal):** Communication occurring strictly within the local area network or local host loopback (`127.0.0.1`).

---

## ✨ Key Features

- **☀️ Professional Light-Mode Interface:** High-contrast, clean typography, balanced medium sizing, and clear visual hierarchy optimized for presentations and extended analysis.
- **🏷️ Real-World Entity Resolution:** Translates raw IP and port combinations into readable names such as `Google Chrome (Local Host) ➔ Cloudflare DNS Resolver`.
- **↕️ Inbound vs. Outbound Separation:** Accurately separates Download and Upload statistics with live byte counters and an interactive balance ratio bar.
- **⚡ Live Network Velocity:** Real-time calculation of Packets Per Second (PPS) and bandwidth throughput (KB/s and MB/s).
- **📊 Protocol Distribution:** Color-coded protocol categorization covering TCP, UDP, ICMP (Ping), and ARP.
- **🔬 Deep Packet Inspection (DPI) Modal:** Click any packet row to inspect its visual flow diagram, Layer 2 Ethernet headers, Layer 3 IPv4 metadata, Layer 4 TCP/UDP flags and sequence numbers, and Wireshark-style Hex/ASCII dump.
- **🔍 Instant Filtering & Search:** Filter by protocol tabs (All, TCP, UDP, ICMP, ARP) or search by process name, IP address, or port.
- **🛡️ Root-Free Simulation Mode:** Automatically simulates realistic network traffic when executed without root privileges, ensuring easy demonstration in any environment.
- **💾 Forensic PCAP & JSON Export:** 1-click download of captured packets in standard `.pcap` format for Wireshark, or `.json` for programmatic analysis.

---

## 📁 System Architecture & File Structure

```
packet_sniffer_project/
├── app.py                  # Flask web server and REST API endpoints
├── main.py                 # Unified launcher script (Web Dashboard & CLI modes)
├── sniffer.py              # Scapy capture engine (Live raw sockets & simulated stream)
├── monitor.py              # Thread-safe traffic statistics and metric collector
├── process_tracker.py      # Socket-to-process mapper using psutil and service tables
├── templates/
│   └── dashboard.html      # Responsive professional light-mode web dashboard
├── utils/
│   ├── __init__.py
│   └── packet_utils.py     # Entity resolution, flow classification, hexdump formatter
├── requirements.txt        # Minimal Python dependencies (Flask, Scapy, psutil)
└── README.md               # Complete project documentation and viva preparation guide
```

---

## 🛠️ Installation & Prerequisites

### 1. Prerequisites:
- Python 3.8 or higher
- Linux (Ubuntu, Debian, Kali, Fedora, Arch) or macOS / Windows

### 2. Set Up Virtual Environment:
```bash
cd /home/lynx/packet_sniffer_project
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies:
```bash
pip install -r requirements.txt
```

---

## 🚀 How to Run: Web Dashboard

### Mode 1: Safe Demonstration Mode (No Root / Sudo Required)
When executed without root privileges, the sniffer automatically operates in Safe Simulation Mode, generating realistic multi-protocol traffic for demonstration:
```bash
python3 app.py
# or
python3 main.py
```
- Open your browser at: **`http://127.0.0.1:5000`**

### Mode 2: Live Hardware Packet Capture (Requires Root / Sudo)
To capture real packets passing through your physical network adapters (Wi-Fi `wlan0`, Ethernet `eth0`):
```bash
sudo .venv/bin/python3 app.py
# or
sudo .venv/bin/python3 main.py
```
- Open your browser at: **`http://127.0.0.1:5000`**

---

## 💻 How to Run: CLI Terminal Mode

For headless servers or direct console monitoring without launching a web browser:

```bash
# Launch terminal live sniffer:
python3 main.py --cli

# Capture 25 packets on a specific interface:
sudo python3 main.py --cli -i wlan0 -c 25

# Capture traffic with a BPF filter (e.g., HTTP traffic):
python3 main.py --cli -f "tcp port 80"

# Run terminal mode in demonstration mode:
python3 main.py --cli --demo -c 10
```

---

## 🖥️ Dashboard Interface Walkthrough

1. **Header Toolbar:**
   - Real-time status indicator (`🟢 Sniffer Running` or `⚪ Sniffer Idle`).
   - Live session timer displaying active capture duration.
   - Global capture controls: **Start Sniffing**, **Stop Sniffing**, **Clear Buffer**, and **Export (.PCAP / .JSON)**.
2. **Configuration Deck:**
   - **Interface Selector:** Select specific hardware adapters (`wlan0`, `eth0`, `lo`) or let the system auto-detect.
   - **Capture Mode:** Toggle between **Safe Demo (Simulation)** and **Live Network Capture**.
   - **Protocol Filter Tabs:** Instant filters for All, TCP, UDP, ICMP, and ARP.
   - **Search Input:** Real-time search across entity names, IP addresses, and port numbers.
3. **KPI Metrics Cards:**
   - **Total Packets:** Total frame count recorded in memory buffer.
   - **Download (Inbound):** Inbound byte volume and percentage.
   - **Upload (Outbound):** Outbound byte volume and percentage.
   - **Throughput Velocity:** Packets per second (PPS) and instantaneous data rate (KB/s).
4. **Traffic Balance & Protocol Distribution:**
   - Visual dual-tone balance bar illustrating the Download vs. Upload traffic ratio.
   - Percentage breakdown badges for TCP, UDP, ICMP, and ARP packets.
5. **Interactive Packet Table:**
   - Visual color coding per protocol and direction.
   - Source entity with local application badge and port number.
   - Destination entity with remote service resolution.
   - Packet length and quick-inspect action trigger.
6. **Deep Packet Inspector (DPI) Modal:**
   - High-contrast visual flow banner: `[ Source Entity ] ──( Protocol & Direction )──> [ Destination Entity ]`.
   - Structured layer tabs:
     - **Ethernet (L2):** Source and Destination MAC addresses.
     - **IPv4 (L3):** Source/Destination IPs, TTL, Header Length, and Checksum.
     - **Transport (L4):** Ports, Sequence Numbers, Acknowledgment numbers, and TCP Flags.
     - **Payload & Hex Dump:** Full Wireshark-style byte offset, hexadecimal values, and ASCII representation.

---

## 🎓 Theoretical Networking Guide (Viva / Presentation)

### 1. How does Direction Detection (Upload vs. Download) work?
- The sniffer examines IP address classifications in `utils/packet_utils.py`:
  - RFC 1918 private IPv4 ranges (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) and loopback (`127.0.0.1`).
- If the **Source IP** is private/local and the **Destination IP** is a public internet address:
  $$\text{Flow} = \text{Upload (Outbound } \uparrow)$$
- If the **Source IP** is a public internet address and the **Destination IP** is private/local:
  $$\text{Flow} = \text{Download (Inbound } \downarrow)$$
- If both IPs are private or loopback:
  $$\text{Flow} = \text{Local LAN / Host Internal } \leftrightarrow$$

### 2. How does Entity and Process Resolution work?
- **Local Endpoints:** `process_tracker.py` inspects the Linux socket table via `psutil.net_connections()`. When an active socket port matches a packet's local port, the associated process name (e.g., `chrome`, `firefox`, `code`) is resolved.
- **Remote Endpoints:** Public IP addresses are matched against a high-speed in-memory resolution cache combining reverse DNS lookups (`socket.gethostbyaddr`) and well-known service IP prefixes (e.g., Google DNS `8.8.8.8`, Cloudflare `1.1.1.1`, GitHub, AWS).

### 3. Why are multi-threading and non-blocking queues necessary?
Packet arrival on busy networks occurs asynchronously and at high velocity. If packet parsing or database writes were performed on the main web server thread, frames would be dropped. The engine uses a background capture thread (`threading.Thread`) coupled with bounded in-memory collections (`collections.deque(maxlen=1000)`) protected by thread locks (`threading.Lock()`).

---

## ❓ Troubleshooting & Frequently Asked Questions

- **Issue: "Address already in use" on Port 5000**
  - Launch with a custom port:
    ```bash
    python3 app.py 8080
    # or
    python3 main.py --port 8080
    ```
- **Issue: "Permission Denied / Operation not permitted"**
  - Raw network socket capture requires Linux root privileges:
    ```bash
    sudo .venv/bin/python3 app.py
    ```
  - Alternatively, choose **Safe Simulation Mode** in the dashboard or run without sudo to capture simulated network traffic safely.

---

## 📜 License
This project is developed for educational, academic, and research purposes.
