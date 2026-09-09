from datetime import datetime


def get_protocol_name(protocol_num):
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }

    return protocols.get(protocol_num, "UNKNOWN")


def create_packet_summary(
    src_ip,
    dst_ip,
    protocol,
    src_port=0,
    dst_port=0,
    size=0,
    flags=""
):

    return {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "src_mac": "-",
        "dst_mac": "-",

        "src_ip": src_ip,
        "dst_ip": dst_ip,

        "protocol": protocol,

        "src_port": src_port,
        "dst_port": dst_port,

        "size": size,
        "flags": flags
    }


def extract_from_scapy(packet):
    
    from scapy.all import IP, TCP, UDP, ICMP, Ether

    packet_dict = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

        "src_mac": "-",
        "dst_mac": "-",

        "src_ip": "-",
        "dst_ip": "-",

        "protocol": "UNKNOWN",

        "src_port": 0,
        "dst_port": 0,

        "size": len(packet),

        "flags": ""
    }

   
    if packet.haslayer(Ether):
        packet_dict["src_mac"] = packet[Ether].src
        packet_dict["dst_mac"] = packet[Ether].dst

    
    if packet.haslayer(IP):

        packet_dict["src_ip"] = packet[IP].src
        packet_dict["dst_ip"] = packet[IP].dst

  
    if packet.haslayer(TCP):

        packet_dict["protocol"] = "TCP"

        packet_dict["src_port"] = packet[TCP].sport
        packet_dict["dst_port"] = packet[TCP].dport

        packet_dict["flags"] = str(packet[TCP].flags)


    elif packet.haslayer(UDP):

        packet_dict["protocol"] = "UDP"

        packet_dict["src_port"] = packet[UDP].sport
        packet_dict["dst_port"] = packet[UDP].dport

    elif packet.haslayer(ICMP):

        packet_dict["protocol"] = "ICMP"

    return packet_dict


def print_packet(packet_dict):
    

    print("-" * 60)

    print(f"Time: {packet_dict.get('time', '-')}")

    
    src_mac = packet_dict.get("src_mac", "-")
    dst_mac = packet_dict.get("dst_mac", "-")

    if src_mac != "-":
        print(f"Source MAC:       {src_mac}")

    if dst_mac != "-":
        print(f"Destination MAC:  {dst_mac}")

    print(
        f"Source IP:        "
        f"{packet_dict.get('src_ip', '-')}"
    )

    print(
        f"Destination IP:   "
        f"{packet_dict.get('dst_ip', '-')}"
    )

    protocol = packet_dict.get("protocol", "-")

    print(f"Protocol:         {protocol}")

  
    if protocol in ["TCP", "UDP"]:

        print(
            f"Source Port:      "
            f"{packet_dict.get('src_port', '-')}"
        )

        print(
            f"Destination Port: "
            f"{packet_dict.get('dst_port', '-')}"
        )

  
    flags = packet_dict.get("flags", "")

    if flags:
        print(f"Flags:            {flags}")

    print(
        f"Packet Size:      "
        f"{packet_dict.get('size', 0)} bytes"
    )

    print("-" * 60)