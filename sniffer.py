import sys
from scapy.all import sniff
from utils.packet_utils import extract_from_scapy, print_packet


captured_packets = []


def process_packet(scapy_packet):
    
    try:
        info = extract_from_scapy(scapy_packet)
        captured_packets.append(info)
        print(info)
        print_packet(info)
    except Exception as e:
        print(f" Error processing packet: {e}")


def start_sniffing(interface=None, packet_count=10, timeout=30):
   
    print("=" * 60)
    print(" LIVE PACKET SNIFFER STARTED")
    print("=" * 60)
    print(f" Interface:     {interface or 'Default (auto-select)'}")
    print(f" Target Count:  {packet_count} packets")
    print(f"⏱  Timeout:       {timeout} seconds")
    print("-" * 60)
    print(" Tip: Open a browser or run 'ping google.com' in another")
    print("   terminal to generate network traffic.")
    print(" Press Ctrl+C to stop early")
    print("=" * 60)
    
    try:
        sniff(
            iface=interface,
            prn=process_packet,
            count=packet_count,
            timeout=timeout,
            store=False
        )
    except PermissionError:
        print("\n" + "!" * 60)
        print("PERMISSION DENIED!")
        print("!" * 60)
        print("Packet sniffing requires administrator/root privileges.")
        print("\nHow to fix:")
        print("  • Windows: Run terminal as Administrator")
        print("  • Mac/Linux: Run with sudo")
        print(f"     sudo python {sys.argv[0]}")
        print("\nAlternatively, use loopback interface for testing:")
        print(f"     sudo python {sys.argv[0]} lo0")
        print("!" * 60)
    except Exception as e:
        print(f"\n Unexpected Error: {e}")
    
    print("\n" + "=" * 60)
    print("CAPTURE SUMMARY")
    print("=" * 60)
    print(f"Total packets captured: {len(captured_packets)}")
    
    if captured_packets:
        protocol_counts = {}
        for p in captured_packets:
            proto = p["protocol"]
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        print("\nProtocol Distribution:")
        for proto, count in sorted(protocol_counts.items()):
          
            print(f"  {proto:8s}: {count:3d}")
        
        total_size = sum(p["size"] for p in captured_packets)
        print(f"\nTotal data: {total_size} bytes")
    

    return captured_packets


def get_captured_packets():
 
    return captured_packets


def clear_captured_packets():
    
    global captured_packets
    captured_packets = []


if __name__ == "__main__":
    if len(sys.argv) > 1:
        iface = sys.argv[1]
    else:
        iface = None
    
    start_sniffing(interface=iface, packet_count=10, timeout=30)