import random
import time

from utils.packet_utils import (
    get_protocol_name,
    create_packet_summary,
    print_packet
)


def generate_mock_packet():

    src_ip = f"192.168.1.{random.randint(2, 50)}"

    dst_ip = f"192.168.1.{random.randint(100, 200)}"

    protocol_num = random.choice([1, 6, 17])

    protocol = get_protocol_name(protocol_num)

    if protocol in ["TCP", "UDP"]:

        src_port = random.randint(40000, 65000)

        dst_port = random.choice([
            80,
            443,
            53,
            22,
            8080
        ])

    else:

        src_port = 0
        dst_port = 0

    size = random.randint(40, 1500)

    flags = ""

    if protocol == "TCP":

        flags = random.choice([
            "SYN",
            "ACK",
            "SYN-ACK",
            "FIN",
            "PSH-ACK"
        ])

    return create_packet_summary(
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
        size,
        flags
    )


def main():

    print("=" * 60)
    print(" MOCK PACKET ANALYZER")
    print("   (Practice tool — no real network needed)")
    print("=" * 60)

    captured_packets = []

    total_packets = 10

    for i in range(1, total_packets + 1):

        print(f"\n Packet #{i} of {total_packets}")

        packet = generate_mock_packet()

        print_packet(packet)

        captured_packets.append(packet)

        time.sleep(0.5)

    print("\n" + "=" * 60)

    print(" CAPTURE SUMMARY")

    print("=" * 60)

    print(
        f"Total packets captured: "
        f"{len(captured_packets)}"
    )

    protocol_counts = {}

    for packet in captured_packets:

        proto = packet["protocol"]

        protocol_counts[proto] = (
            protocol_counts.get(proto, 0) + 1
        )

    print("\nProtocol Distribution:")

    for proto, count in protocol_counts.items():

        print(f"  • {proto}: {count}")

    total_size = sum(
        packet["size"]
        for packet in captured_packets
    )

    print(
        f"\nTotal data captured: "
        f"{total_size} bytes"
    )

    print("=" * 60)


if __name__ == "__main__":
    main()