"""Network Packet Sniffer & Traffic Monitor - Main Entry Point.

This file serves as the main launcher for the project:
1. By default, it launches the Interactive Web Dashboard:
     python main.py
2. You can also run it in Terminal / CLI mode:
     python main.py --cli
3. For live hardware packet capture with full permissions:
     sudo python main.py
"""
import argparse
import os
import sys

from monitor import TrafficMonitor, format_summary


def is_admin():
    """Checks if running with root / administrator privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())


def run_cli_mode(args):
    """Runs the packet sniffer in the terminal (command-line mode)."""
    from sniffer import Sniffer
    from utils.packet_utils import format_packet

    monitor = TrafficMonitor()
    # Print packet summary line as soon as it arrives
    sniffer = Sniffer(monitor=monitor, on_packet=lambda pkt: print(format_packet(pkt)))

    simulated = args.demo or not is_admin()

    print("=" * 65)
    print(" 📡 NETWORK PACKET SNIFFER (CLI MODE)")
    print("=" * 65)
    if simulated:
        print(" [!] Mode: SIMULATED / DEMO TRAFFIC (No root required)")
    else:
        print(f" [+] Interface: {args.iface or 'Auto-detect (All)'}")
        if args.filter:
            print(f" [+] Filter:    {args.filter}")
    if args.count:
        print(f" [+] Limit:     {args.count} packets")
    if args.timeout:
        print(f" [+] Timeout:   {args.timeout} seconds")
    if args.write:
        print(f" [+] PCAP File: {args.write}")
    print("-" * 65)
    print(" Capturing packets... Press Ctrl+C at any time to stop.")
    print("-" * 65)

    try:
        sniffer.start(
            iface=args.iface,
            bpf=args.filter,
            count=args.count,
            timeout=args.timeout,
            pcap=args.write,
            simulated=simulated,
        )
        sniffer.wait()
    except KeyboardInterrupt:
        print("\n[!] Stopping packet sniffer (interrupted by user)...")
    except Exception as e:
        sys.exit(f"\n[!] Error during capture: {e}")
    finally:
        sniffer.stop()

    if sniffer.get_error():
        print(f"\n[!] Sniffer Error: {sniffer.get_error()}")

    # Print final summary statistics
    print("\n" + format_summary(monitor.stats()))
    if args.write:
        print(f"\n[+] Saved PCAP capture to: {args.write}")


def main():
    """Parses command line arguments and starts web or CLI mode."""
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer & Traffic Analysis Dashboard"
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run in terminal CLI mode instead of the web dashboard",
    )
    parser.add_argument(
        "-i", "--iface",
        help="Network interface to sniff on (e.g. eth0, wlan0, lo)",
    )
    parser.add_argument(
        "-f", "--filter",
        help='BPF filter syntax, e.g. "tcp", "udp", "port 80", "icmp"',
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Stop after N packets (0 = unlimited)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=None,
        help="Stop after N seconds",
    )
    parser.add_argument(
        "-w", "--write",
        metavar="FILE.pcap",
        help="Export captured packets to a PCAP file",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Force simulated demo traffic (no root needed)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Web dashboard port (default: 5000)",
    )
    args = parser.parse_args()

    # If --cli flag is explicitly passed, run in terminal
    if args.cli:
        run_cli_mode(args)
    else:
        # Default behavior: Launch Web Dashboard
        from app import run
        run(port=args.port)


if __name__ == "__main__":
    main()
