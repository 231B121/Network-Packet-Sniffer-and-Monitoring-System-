"""Network Packet Utility Functions.

This module provides helper utilities to decode Scapy packets into clean Python
dictionaries, format Wireshark-style hex dumps, map protocol numbers to names,
resolve human-readable entities (e.g. Google Chrome on Local Host -> Google Services),
and determine traffic direction (Inbound vs Outbound).
"""
from datetime import datetime
import ipaddress
import socket
import threading

# Well-known static hosts cache for instant lookup without network delay
_DNS_CACHE = {
    "1.1.1.1": "Cloudflare DNS Resolver",
    "1.0.0.1": "Cloudflare DNS Resolver",
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "9.9.9.9": "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "127.0.0.1": "Localhost (Loopback)",
    "::1": "Localhost (Loopback)",
}
_DNS_LOCK = threading.Lock()
_RESOLVING_SET = set()


def is_private_ip(ip):
    """Checks whether an IP address belongs to a local private network or loopback."""
    if not ip or ip == "-" or ip == "0.0.0.0":
        return True
    try:
        return ipaddress.ip_address(ip).is_private or ip in ("127.0.0.1", "localhost", "::1")
    except Exception:
        return False


def _bg_reverse_dns(ip):
    """Performs reverse DNS lookup in a background thread to prevent blocking sniffer."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        h_lower = host.lower()
        friendly = None
        if any(k in h_lower for k in ("google", "1e100", "youtube", "gmail")):
            friendly = f"Google Services ({host})"
        elif any(k in h_lower for k in ("cloudflare", "1.1.1.1")):
            friendly = f"Cloudflare ({host})"
        elif any(k in h_lower for k in ("github", "ghcr")):
            friendly = f"GitHub Cloud ({host})"
        elif any(k in h_lower for k in ("microsoft", "azure", "live.com", "bing")):
            friendly = f"Microsoft / Azure ({host})"
        elif any(k in h_lower for k in ("amazon", "aws", "cloudfront")):
            friendly = f"Amazon AWS ({host})"
        elif any(k in h_lower for k in ("facebook", "fbcdn", "whatsapp", "instagram", "meta")):
            friendly = f"Meta Services ({host})"
        elif "spotify" in h_lower:
            friendly = f"Spotify ({host})"
        elif "discord" in h_lower:
            friendly = f"Discord ({host})"
        else:
            friendly = host

        with _DNS_LOCK:
            _DNS_CACHE[ip] = friendly
    except Exception:
        with _DNS_LOCK:
            _DNS_CACHE[ip] = None
    finally:
        with _DNS_LOCK:
            _RESOLVING_SET.discard(ip)


def resolve_entity(ip, port=None, is_source=True, app_name=None):
    """Resolves an IP + port into a clear professional entity name.

    Examples:
      - '192.168.1.15' + app 'Google Chrome' -> 'Google Chrome (Local Host)'
      - '192.168.1.1' -> 'Default Gateway (192.168.1.1)'
      - '142.250.190.46' -> 'Google Services (ord37...)'
      - '1.1.1.1' -> 'Cloudflare DNS Resolver'
    """
    if not ip or ip == "-":
        return "Unknown Endpoint"

    # 1. Localhost / Loopback
    if ip in ("127.0.0.1", "localhost", "::1"):
        if app_name and app_name != "Unknown":
            return f"{app_name} (Localhost)"
        return "Localhost (Loopback)"

    # 2. Local Private Network (Gateway or Host)
    if is_private_ip(ip):
        if ip.endswith(".1"):
            return f"Default Gateway ({ip})"
        if app_name and app_name != "Unknown":
            return f"{app_name} (Local Host)"
        return f"Local Host ({ip})"

    # 3. Public Internet Endpoint
    with _DNS_LOCK:
        if ip in _DNS_CACHE and _DNS_CACHE[ip]:
            return _DNS_CACHE[ip]

        # Trigger background reverse DNS if not already requested
        if ip not in _DNS_CACHE and ip not in _RESOLVING_SET:
            _RESOLVING_SET.add(ip)
            threading.Thread(target=_bg_reverse_dns, args=(ip,), daemon=True).start()

    # Fallback to port service description while DNS resolves
    if port == 443:
        return f"Web Server (HTTPS: {ip})"
    if port == 80:
        return f"Web Server (HTTP: {ip})"
    if port == 53:
        return f"DNS Server ({ip})"
    if port == 22:
        return f"SSH Server ({ip})"
    return f"Remote Server ({ip})"


def determine_flow(src_ip, dst_ip, src_entity="", dst_entity=""):
    """Determines whether packet is Outbound (Upload), Inbound (Download), or Local."""
    src_is_priv = is_private_ip(src_ip)
    dst_is_priv = is_private_ip(dst_ip)

    if src_ip in ("127.0.0.1", "::1") and dst_ip in ("127.0.0.1", "::1"):
        return {
            "direction": "loopback",
            "direction_label": "Loopback",
            "flow_summary": f"{src_entity} ➔ {dst_entity}",
        }

    if src_is_priv and not dst_is_priv:
        return {
            "direction": "outgoing",
            "direction_label": "Outbound ⬆",
            "flow_summary": f"{src_entity} ➔ {dst_entity}",
        }
    elif not src_is_priv and dst_is_priv:
        return {
            "direction": "incoming",
            "direction_label": "Inbound ⬇",
            "flow_summary": f"{src_entity} ➔ {dst_entity}",
        }
    else:
        return {
            "direction": "local",
            "direction_label": "Local LAN 🔄",
            "flow_summary": f"{src_entity} ➔ {dst_entity}",
        }


def get_protocol_name(protocol_num):
    """Maps standard IANA protocol numbers to common names (TCP, UDP, ICMP, etc.)."""
    protocols = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        89: "OSPF",
    }
    return protocols.get(protocol_num, f"Proto-{protocol_num}")


def format_hexdump(data, length=16):
    """Generates standard side-by-side Hex and ASCII dump (Wireshark / tcpdump style)."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    if not isinstance(data, (bytes, bytearray)):
        return ""

    lines = []
    for i in range(0, len(data), length):
        chunk = data[i : i + length]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(length * 3)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def create_packet_summary(
    src_ip,
    dst_ip,
    protocol,
    src_port=0,
    dst_port=0,
    size=0,
    flags="",
    src_mac="-",
    dst_mac="-",
    summary="",
    payload_preview="",
    app=None,
    src_entity=None,
    dst_entity=None,
):
    """Creates a normalized packet dictionary with real entity resolution and direction."""
    now = datetime.now()
    if isinstance(flags, list):
        flag_list = flags
        flag_str = ",".join(flags)
    elif isinstance(flags, str) and flags:
        flag_list = [f.strip() for f in flags.split(",") if f.strip()]
        flag_str = flags
    else:
        flag_list = []
        flag_str = ""

    # Resolve human readable entities if not explicitly provided
    resolved_src = src_entity or resolve_entity(src_ip, port=src_port, is_source=True, app_name=app)
    resolved_dst = dst_entity or resolve_entity(dst_ip, port=dst_port, is_source=False)

    flow_info = determine_flow(src_ip, dst_ip, resolved_src, resolved_dst)

    if not summary:
        if protocol in ("TCP", "UDP"):
            summary = f"{resolved_src} -> {resolved_dst}"
            if flag_str:
                summary += f" [{flag_str}]"
        elif protocol == "ICMP":
            summary = f"{resolved_src} -> {resolved_dst} (ICMP)"
        else:
            summary = f"{resolved_src} -> {resolved_dst} ({protocol})"

    return {
        "time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": now.timestamp(),
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_entity": resolved_src,
        "dst_entity": resolved_dst,
        "direction": flow_info["direction"],
        "direction_label": flow_info["direction_label"],
        "flow_summary": flow_info["flow_summary"],
        "protocol": protocol,
        "src_port": src_port if src_port != 0 else None,
        "dst_port": dst_port if dst_port != 0 else None,
        "size": size,
        "flags": flag_list,
        "flags_str": flag_str,
        "summary": summary,
        "payload_preview": payload_preview,
        "raw_hex": "",
        "app": app or "Unknown",
    }


def extract_from_scapy(packet):
    """Decodes a Scapy packet into layer-by-layer fields with entity resolution."""
    from scapy.all import ARP, ICMP, IP, IPv6, Raw, TCP, UDP, Ether

    now = datetime.now()
    raw_bytes = bytes(packet)

    packet_dict = {
        "time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "timestamp": now.timestamp(),
        "src_mac": "-",
        "dst_mac": "-",
        "src_ip": "-",
        "dst_ip": "-",
        "src_entity": "Unknown Endpoint",
        "dst_entity": "Unknown Endpoint",
        "direction": "local",
        "direction_label": "Local LAN 🔄",
        "flow_summary": "",
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "size": len(raw_bytes),
        "flags": [],
        "flags_str": "",
        "ttl": None,
        "summary": packet.summary() if hasattr(packet, "summary") else "",
        "payload_preview": "",
        "raw_hex": raw_bytes[:160].hex(),
        "hexdump": format_hexdump(raw_bytes[:256]),
        "app": "Unknown",
    }

    # 1. Data Link Layer: Ethernet
    if packet.haslayer(Ether):
        eth = packet[Ether]
        packet_dict["src_mac"] = str(eth.src).upper()
        packet_dict["dst_mac"] = str(eth.dst).upper()
        packet_dict["eth_type"] = f"0x{eth.type:04x}"

    # 2. Network Layer: IPv4 / IPv6 / ARP
    if packet.haslayer(IP):
        ip = packet[IP]
        packet_dict["src_ip"] = ip.src
        packet_dict["dst_ip"] = ip.dst
        packet_dict["ttl"] = ip.ttl
        packet_dict["protocol"] = get_protocol_name(ip.proto)

    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        packet_dict["src_ip"] = ip6.src
        packet_dict["dst_ip"] = ip6.dst
        packet_dict["protocol"] = "IPv6"

    elif packet.haslayer(ARP):
        arp = packet[ARP]
        packet_dict["protocol"] = "ARP"
        packet_dict["src_ip"] = arp.psrc
        packet_dict["dst_ip"] = arp.pdst
        op_name = "Request" if arp.op == 1 else "Reply" if arp.op == 2 else f"Op {arp.op}"
        packet_dict["summary"] = f"ARP {op_name}: Who has {arp.pdst}? Tell {arp.psrc}"

    # 3. Transport Layer: TCP / UDP / ICMP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        packet_dict["protocol"] = "TCP"
        packet_dict["src_port"] = int(tcp.sport)
        packet_dict["dst_port"] = int(tcp.dport)

        flag_names = []
        f = int(tcp.flags)
        if f & 0x02: flag_names.append("SYN")
        if f & 0x10: flag_names.append("ACK")
        if f & 0x01: flag_names.append("FIN")
        if f & 0x04: flag_names.append("RST")
        if f & 0x08: flag_names.append("PSH")
        if f & 0x20: flag_names.append("URG")

        packet_dict["flags"] = flag_names
        packet_dict["flags_str"] = ",".join(flag_names)
        packet_dict["seq_num"] = tcp.seq
        packet_dict["ack_num"] = tcp.ack

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        packet_dict["protocol"] = "UDP"
        packet_dict["src_port"] = int(udp.sport)
        packet_dict["dst_port"] = int(udp.dport)

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        packet_dict["protocol"] = "ICMP"
        type_map = {8: "Echo Request (Ping)", 0: "Echo Reply (Pong)", 3: "Destination Unreachable", 11: "Time Exceeded"}
        t_name = type_map.get(icmp.type, f"Type {icmp.type}")
        packet_dict["icmp"] = t_name
        packet_dict["icmp_type"] = icmp.type
        packet_dict["icmp_code"] = icmp.code

    # 4. Resolve Entities and Direction
    src_ip = packet_dict["src_ip"]
    dst_ip = packet_dict["dst_ip"]
    sport = packet_dict["src_port"]
    dport = packet_dict["dst_port"]

    resolved_src = resolve_entity(src_ip, port=sport, is_source=True)
    resolved_dst = resolve_entity(dst_ip, port=dport, is_source=False)
    flow_info = determine_flow(src_ip, dst_ip, resolved_src, resolved_dst)

    packet_dict["src_entity"] = resolved_src
    packet_dict["dst_entity"] = resolved_dst
    packet_dict["direction"] = flow_info["direction"]
    packet_dict["direction_label"] = flow_info["direction_label"]
    packet_dict["flow_summary"] = flow_info["flow_summary"]

    # 5. Application / Payload Data
    if packet.haslayer(Raw):
        raw_payload = bytes(packet[Raw].load)
        preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_payload[:60])
        packet_dict["payload_preview"] = preview

    return packet_dict


def format_packet(info):
    """Formats a packet dictionary into a clean terminal string."""
    t = info.get("time", "").split(" ")[-1]
    proto = info.get("protocol", "OTHER")
    src = info.get("src_entity", info.get("src_ip", "-"))
    dst = info.get("dst_entity", info.get("dst_ip", "-"))
    direction = info.get("direction_label", "")
    size = info.get("size", 0)

    return f"[{t}] {proto:<5} {direction:<12} {src:<32} ➔ {dst:<32} {size:>5}B"


def print_packet(packet_dict):
    """Pretty prints a packet dictionary to the terminal."""
    print("-" * 60)
    print(f"Time:             {packet_dict.get('time', '-')}")
    print(f"Direction:        {packet_dict.get('direction_label', '-')}")
    print(f"Source:           {packet_dict.get('src_entity', '-')} ({packet_dict.get('src_ip', '-')})")
    print(f"Destination:      {packet_dict.get('dst_entity', '-')} ({packet_dict.get('dst_ip', '-')})")
    print(f"Protocol:         {packet_dict.get('protocol', '-')}")
    if packet_dict.get("src_port") is not None:
        print(f"Source Port:      {packet_dict.get('src_port')}")
    if packet_dict.get("dst_port") is not None:
        print(f"Destination Port: {packet_dict.get('dst_port')}")
    flags = packet_dict.get("flags_str") or ",".join(packet_dict.get("flags", []))
    if flags:
        print(f"Flags:            {flags}")
    print(f"Packet Size:      {packet_dict.get('size', 0)} bytes")
    if packet_dict.get("summary"):
        print(f"Summary:          {packet_dict.get('summary')}")
    print("-" * 60)
