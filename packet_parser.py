
import struct
def parse_ethernet_header(data):
    dest_mac = data[0:6]
    src_mac = data[6:12]
    eth_type = data[12:14]
    
    dest_mac_str = ':'.join(f'{b:02x}' for b in dest_mac)
    src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)
    eth_type_int = struct.unpack('!H', eth_type)[0]
    
    eth_type_map = {
        0x0800: "IPv4", 
        0x0806: "ARP",
        0x86DD: "IPv6"
    }
    
    return {
        "dest_mac": dest_mac_str.upper(),
        "src_mac": src_mac_str.upper(),
        "eth_type": eth_type_map.get(eth_type_int, f"Unknown (0x{eth_type_int:04x})"),
        "eth_type_raw": eth_type_int,
        "header_length": 14
    }


def parse_ip_header(data):
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    header_length = ihl * 4
    
    total_length = struct.unpack('!H', data[2:4])[0]
    ttl = data[8]
    protocol_num = data[9]
    protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP"}
    protocol = protocol_map.get(protocol_num, f"Other ({protocol_num})")
    
    src_ip = '.'.join(str(b) for b in data[12:16])
    dst_ip = '.'.join(str(b) for b in data[16:20])
    print("Data from IP : ", data)
    return {
        "version": version,
        "header_length": header_length,
        "total_length": total_length,
        "ttl": ttl,
        "protocol": protocol,
        "protocol_num": protocol_num,
        "src_ip": src_ip,
        "dst_ip": dst_ip
    }


def parse_tcp_header(data):
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    seq_num = struct.unpack('!I', data[4:8])[0]
    ack_num = struct.unpack('!I', data[8:12])[0]
    data_offset = (data[12] >> 4) * 4
    flags_byte = ((data[12] & 0x0F) << 8) | data[13]
    
    flag_names = []
    if flags_byte & 0x002: flag_names.append("SYN")
    if flags_byte & 0x010: flag_names.append("ACK")
    if flags_byte & 0x001: flag_names.append("FIN")
    if flags_byte & 0x004: flag_names.append("RST")
    if flags_byte & 0x008: flag_names.append("PSH")
    if flags_byte & 0x020: flag_names.append("URG")
    
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "seq_num": seq_num,
        "ack_num": ack_num,
        "header_length": data_offset,
        "flags_raw": f"0x{flags_byte:03x}",
        "flags": flag_names if flag_names else ["NONE"]
    }


def parse_udp_header(data):
    src_port = struct.unpack('!H', data[0:2])[0]
    dst_port = struct.unpack('!H', data[2:4])[0]
    length = struct.unpack('!H', data[4:6])[0]
    
    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length
    }


def parse_icmp_header(data):
    icmp_type = data[0]
    icmp_code = data[1]
    
    type_map = {
        8: "Echo Request (ping)",
        0: "Echo Reply (pong)",
        3: "Destination Unreachable",
        11: "Time Exceeded"
    }
    
    return {
        "type": icmp_type,
        "type_name": type_map.get(icmp_type, f"Type {icmp_type}"),
        "code": icmp_code
    }


def analyze_packet(raw_bytes):
    print("=" * 60)
    print("PACKET ANALYSIS")
    print("=" * 60)
    
    eth = parse_ethernet_header(raw_bytes)
    print("\n ETHERNET FRAME:")
    print(f"   Source MAC:      {eth['src_mac']}")
    print(f"   Destination MAC: {eth['dest_mac']}")
    print(f"   EtherType:       {eth['eth_type']}")
    
    if eth['eth_type_raw'] != 0x0800:
        print("   ⚠️ Not an IPv4 packet. Stopping here.")
        return
    
    ip_data = raw_bytes[eth['header_length']:]
    ip = parse_ip_header(ip_data)
    print("\n IP HEADER:")
    print(f"   Version:         IPv{ip['version']}")
    print(f"   Header Length:   {ip['header_length']} bytes")
    print(f"   Total Length:    {ip['total_length']} bytes")
    print(f"   TTL:             {ip['ttl']}")
    print(f"   Protocol:        {ip['protocol']}")
    print(f"   Source IP:       {ip['src_ip']}")
    print(f"   Destination IP:  {ip['dst_ip']}")
    
    transport_data = ip_data[ip['header_length']:]
    
    
    if ip['protocol_num'] == 6:
        tcp = parse_tcp_header(transport_data)
        print("\n🔌 TCP HEADER:")
        print(f"   Source Port:     {tcp['src_port']}")
        print(f"   Destination Port:{tcp['dst_port']}")
        print(f"   Sequence Number: {tcp['seq_num']}")
        print(f"   Ack Number:      {tcp['ack_num']}")
        print(f"   Header Length:   {tcp['header_length']} bytes")
        print(f"   Flags:           {', '.join(tcp['flags'])} ({tcp['flags_raw']})")
        
    elif ip['protocol_num'] == 17:
        udp = parse_udp_header(transport_data)
        print("\n UDP HEADER:")
        print(f"   Source Port:     {udp['src_port']}")
        print(f"   Destination Port:{udp['dst_port']}")
        print(f"   Length:          {udp['length']} bytes")
        
    elif ip['protocol_num'] == 1:
        icmp = parse_icmp_header(transport_data)
        print("\nICMP HEADER:")
        print(f"   Type:            {icmp['type_name']}")
        print(f"   Code:            {icmp['code']}")
    
    print("\n" + "=" * 60)


def create_mock_tcp_packet():
    import random
    eth_header = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00
    ])
    
    version_ihl = 0x45
    tos = 0x00
    total_length = 0x003C
    identification = random.randint(0, 65535)
    flags_fragment = 0x4000
    ttl = 64
    protocol = 6
    checksum = 0x0000
    src_ip = bytes([192, 168, 1, 10])
    dst_ip = bytes([192, 168, 1, 1])
    
    ip_header = bytes([
        version_ihl, tos,
        (total_length >> 8) & 0xFF, total_length & 0xFF,
        (identification >> 8) & 0xFF, identification & 0xFF,
        (flags_fragment >> 8) & 0xFF, flags_fragment & 0xFF,
        ttl, protocol,
        (checksum >> 8) & 0xFF, checksum & 0xFF,
    ]) + src_ip + dst_ip
    
    src_port = 54321
    dst_port = 80
    seq_num = 1000
    ack_num = 0
    data_offset_flags = (5 << 12) | 0x002
    window = 65535
    tcp_checksum = 0
    urgent = 0
    
    tcp_header = struct.pack('!HHIIHHHH',
        src_port, dst_port, seq_num, ack_num,
        data_offset_flags, window, tcp_checksum, urgent)
    
    return eth_header + ip_header + tcp_header


def create_mock_udp_packet():
    eth_header = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00
    ])
    
    version_ihl = 0x45
    total_length = 0x0028
    src_ip = bytes([192, 168, 1, 20])
    dst_ip = bytes([8, 8, 8, 8])
    
    ip_header = bytes([
        version_ihl, 0x00,
        (total_length >> 8) & 0xFF, total_length & 0xFF,
        0x00, 0x01, 0x00, 0x00,
        64, 17,
        0x00, 0x00,
    ]) + src_ip + dst_ip
    
    src_port = 12345
    dst_port = 53
    length = 20
    udp_checksum = 0
    
    udp_header = struct.pack('!HHHH', src_port, dst_port, length, udp_checksum)
    
    return eth_header + ip_header + udp_header


def create_mock_icmp_packet():
    eth_header = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x08, 0x00
    ])
    
    version_ihl = 0x45
    total_length = 0x001C
    src_ip = bytes([10, 0, 0, 5])
    dst_ip = bytes([10, 0, 0, 1])
    
    ip_header = bytes([
        version_ihl, 0x00,
        (total_length >> 8) & 0xFF, total_length & 0xFF,
        0x00, 0x01, 0x00, 0x00,
        128, 1,
        0x00, 0x00,
    ]) + src_ip + dst_ip
    
    icmp_header = bytes([
        8, 0,
        0x00, 0x00,
        0x00, 0x01,
        0x00, 0x01
    ])
    
    return eth_header + ip_header + icmp_header


def main():
    print("\n" + "=" * 30)
    print("   MOCK PACKET PARSER TEST")
    print("   Testing TCP, UDP, and ICMP packets")
    print("=" * 30 + "\n")
    
    print("\n" + "=" * 30)
    tcp_packet = create_mock_tcp_packet()
    analyze_packet(tcp_packet)
    
    print("\n" + "=" * 30)
    udp_packet = create_mock_udp_packet()
    analyze_packet(udp_packet)
    
    print("\n" + "=" * 30)
    icmp_packet = create_mock_icmp_packet()
    analyze_packet(icmp_packet)
    
    print("\n" + "=" * 60)
    print("✅ All 3 packet types parsed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()