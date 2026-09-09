from scapy.all import get_if_list

interfaces = get_if_list()

print("=" * 50)
print(" Your Computer's Network Interfaces:")
print("=" * 50)

for i, iface in enumerate(interfaces, 1):
    print(f"{i}. {iface}")

print("=" * 50)
print(f"Total interfaces found: {len(interfaces)}")