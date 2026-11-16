"""Network Packet Sniffer Engine using Scapy.

This module provides the multi-threaded Sniffer class that captures network packets
either from live hardware network interfaces (using Scapy's raw sockets) or via
realistic traffic simulation (for safe testing without root privileges).

Features:
  - Live capture on physical or virtual network interfaces (eth0, wlan0, lo).
  - Real entity resolution (Google Chrome, Default Gateway, Cloudflare, etc.).
  - Outbound vs Inbound direction tracking.
  - BPF filter support (e.g. "tcp", "udp port 53", "icmp").
  - Background thread execution with clean start/stop controls.
  - Safe traffic simulation mode (great for offline demos!).
  - Live PCAP file writing for Wireshark analysis.
"""
import random
import sys
import threading
import time

from monitor import TrafficMonitor
from utils.packet_utils import (
    create_packet_summary,
    extract_from_scapy,
    format_hexdump,
    format_packet,
    print_packet,
)


class Sniffer:
    """Manages packet capture in a dedicated background worker thread."""

    def __init__(self, monitor=None, on_packet=None):
        """Initializes the sniffer with an optional monitor and packet callback."""
        self.monitor = monitor or TrafficMonitor()
        self.on_packet = on_packet
        self.thread = None
        self.stop_event = threading.Event()
        self.running = False
        self.error = None
        self.iface = None
        self.bpf = None
        self.pcap_path = None
        self.pcap_writer = None
        self.is_simulated = False
        self.captured_packets = []

    def start(self, iface=None, bpf=None, count=0, timeout=None, pcap=None, simulated=False):
        """Starts packet capture in a background thread."""
        # If already running, stop previous capture cleanly
        if self.thread and self.thread.is_alive():
            self.stop()

        self.running = False
        self.stop_event = threading.Event()
        self.error = None
        self.iface = iface
        self.bpf = bpf
        self.pcap_path = pcap
        self.is_simulated = simulated
        self.running = True

        # Optional PCAP writer for saving packets directly to disk
        if pcap:
            try:
                from scapy.utils import PcapWriter
                self.pcap_writer = PcapWriter(pcap, append=True, sync=True)
            except Exception as e:
                print(f"[!] Warning: Could not initialize PCAP writer: {e}")
                self.pcap_writer = None

        stop_evt = self.stop_event

        # Launch background thread based on mode
        if simulated:
            self.thread = threading.Thread(
                target=self._run_simulated,
                args=(count, timeout, stop_evt),
                daemon=True,
                name="SnifferSimulatorThread",
            )
        else:
            self.thread = threading.Thread(
                target=self._run_live,
                args=(iface, bpf, count, timeout, stop_evt),
                daemon=True,
                name="SnifferLiveThread",
            )

        self.thread.start()
        return True

    def _process_packet(self, scapy_packet):
        """Callback executed for each Scapy packet captured from the wire."""
        if self.stop_event.is_set():
            return

        try:
            # Parse packet headers, resolve entities, and determine flow direction
            info = extract_from_scapy(scapy_packet)
            self.captured_packets.append(info)

            # Record in monitor for traffic statistics
            if self.monitor:
                self.monitor.add(info)

            # Write raw packet to PCAP file if writer is active
            if self.pcap_writer:
                try:
                    self.pcap_writer.write(scapy_packet)
                except Exception:
                    pass

            # Optional real-time callback (e.g. CLI printing)
            if self.on_packet:
                self.on_packet(info)
        except Exception as e:
            print(f"[!] Error processing packet: {e}", file=sys.stderr)

    def _run_live(self, iface, bpf, count, timeout, stop_evt):
        """Live capture loop using Scapy's sniff() function."""
        try:
            from scapy.all import sniff

            deadline = time.time() + timeout if timeout else None

            def should_stop(_pkt):
                if stop_evt.is_set():
                    return True
                if deadline and time.time() >= deadline:
                    return True
                return False

            sniff_kwargs = {
                "iface": iface if iface else None,
                "prn": self._process_packet,
                "stop_filter": should_stop,
                "store": False,
            }
            if bpf:
                sniff_kwargs["filter"] = bpf
            if count and count > 0:
                sniff_kwargs["count"] = count

            sniff(**sniff_kwargs)

        except PermissionError:
            self.error = (
                "Permission denied: Live packet capture requires root privileges. "
                "Run with 'sudo python main.py' or select Safe Simulation Mode in the dashboard."
            )
        except Exception as e:
            self.error = str(e)
        finally:
            if stop_evt is self.stop_event:
                self.running = False
            if self.pcap_writer:
                try:
                    self.pcap_writer.close()
                except Exception:
                    pass

    def _run_simulated(self, count, timeout, stop_evt):
        """Generates realistic simulated network packets for root-less practice and demos."""
        try:
            start_time = time.time()
            packets_sent = 0

            # Realistic daily communication pairs (IP, port, proto, flags, remote entity label, local app)
            common_destinations = [
                ("142.250.190.46", 443, "TCP", ["ACK", "PSH"], "Google Services (HTTPS)", "Google Chrome"),
                ("1.1.1.1", 53, "UDP", [], "Cloudflare DNS Resolver", "systemd-resolved"),
                ("8.8.8.8", 53, "UDP", [], "Google Public DNS", "systemd-resolved"),
                ("104.26.10.228", 80, "TCP", ["ACK"], "Cloudflare Edge (HTTP)", "Web Browser"),
                ("192.168.1.1", 80, "TCP", ["SYN"], "Gateway Admin Interface", "Mozilla Firefox"),
                ("192.168.1.1", 0, "ICMP", [], "Default Gateway", "ICMP Ping"),
                ("185.199.108.153", 443, "TCP", ["ACK", "PSH"], "GitHub API Endpoint", "Visual Studio Code"),
                ("192.168.1.50", 22, "TCP", ["SYN", "ACK"], "OpenSSH Server", "SSH Client"),
                ("35.186.224.25", 443, "TCP", ["ACK"], "Spotify Media Server", "Spotify"),
                ("162.159.135.232", 443, "TCP", ["ACK"], "Discord Gateway API", "Discord"),
            ]

            mac_prefix = "52:54:00:12:34:"

            while not stop_evt.is_set():
                if timeout and (time.time() - start_time) >= timeout:
                    break
                if count and packets_sent >= count:
                    break

                dest_info = random.choice(common_destinations)
                remote_ip, remote_port, proto, flags, remote_entity, app_name = dest_info

                local_ip = f"192.168.1.{random.randint(10, 45)}"
                local_port = random.randint(32768, 61000) if proto in ("TCP", "UDP") else 0
                pkt_size = random.randint(64, 1460)

                # Randomize direction: Outbound (Upload) vs Inbound (Download)
                is_incoming = random.random() < 0.45
                if is_incoming:
                    src_ip = remote_ip
                    dst_ip = local_ip
                    src_port = remote_port
                    dst_port = local_port
                    src_ent = remote_entity
                    dst_ent = f"{app_name} (Local Host)"
                else:
                    src_ip = local_ip
                    dst_ip = remote_ip
                    src_port = local_port
                    dst_port = remote_port
                    src_ent = f"{app_name} (Local Host)"
                    dst_ent = remote_entity

                flag_str = ",".join(flags) if flags else ""
                summary = f"{src_ent} ➔ {dst_ent}"
                if flag_str:
                    summary += f" [{flag_str}]"

                pkt_dict = create_packet_summary(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=proto,
                    src_port=src_port,
                    dst_port=dst_port,
                    size=pkt_size,
                    flags=flags,
                    src_mac=f"{mac_prefix}{random.randint(10, 99):02x}",
                    dst_mac=f"{mac_prefix}{random.randint(10, 99):02x}",
                    summary=summary,
                    app=app_name,
                    src_entity=src_ent,
                    dst_entity=dst_ent,
                )

                if proto == "ICMP":
                    pkt_dict["icmp"] = "Echo Reply" if is_incoming else "Echo Request"
                    pkt_dict["icmp_type"] = 0 if is_incoming else 8
                    pkt_dict["icmp_code"] = 0

                # Generate sample payload bytes for inspection and hex-dump
                fake_payload = bytes(random.randint(32, 126) for _ in range(min(pkt_size, 64)))
                pkt_dict["raw_hex"] = fake_payload.hex()
                pkt_dict["hexdump"] = format_hexdump(fake_payload)

                self.captured_packets.append(pkt_dict)
                if self.monitor:
                    self.monitor.add(pkt_dict)
                if self.on_packet:
                    self.on_packet(pkt_dict)

                packets_sent += 1
                # Realistic packet arrival jitter (50ms - 250ms)
                time.sleep(random.uniform(0.05, 0.25))

        except Exception as e:
            self.error = str(e)
        finally:
            if stop_evt is self.stop_event:
                self.running = False

    def stop(self):
        """Signals the sniffer background thread to stop."""
        self.running = False
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

    def wait(self, timeout=None):
        """Blocks until the sniffer thread terminates."""
        if self.thread:
            self.thread.join(timeout=timeout)

    def is_running(self):
        """Returns True if the sniffer thread is actively running."""
        running = bool(self.running and (self.thread is not None and self.thread.is_alive()))
        if not running:
            self.running = False
        return running

    def get_error(self):
        """Returns any error message encountered during capture."""
        return self.error


# Backward compatibility convenience functions
_legacy_monitor = TrafficMonitor()
_legacy_captured = []


def start_sniffing(interface=None, packet_count=10, timeout=30):
    """Starts standalone console sniffing."""
    global _legacy_captured
    sniffer = Sniffer(monitor=_legacy_monitor, on_packet=lambda i: print(format_packet(i)))
    print("=" * 60)
    print(" LIVE PACKET SNIFFER STARTED")
    print(f" Interface:     {interface or 'Default (auto-select)'}")
    print(f" Target Count:  {packet_count} packets")
    print(f" Timeout:       {timeout} seconds")
    print(" Press Ctrl+C to stop early")
    print("=" * 60)

    sniffer.start(iface=interface, count=packet_count, timeout=timeout)
    try:
        sniffer.wait()
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        sniffer.stop()

    _legacy_captured = sniffer.captured_packets
    from monitor import format_summary
    print("\n" + format_summary(_legacy_monitor.stats()))
    return _legacy_captured
