"""Application & Process Bandwidth Tracker.

Maps network packets (source/destination ports) to active processes and services
(e.g., Web Browsers, DNS Resolver, SSH, Spotify, System Services) using psutil
and well-known port mappings.
"""
import threading
import time
from collections import Counter


def human_bytes(num):
    """Formats byte counts into human-readable strings."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"


# Well-known service port fallbacks when PID is system-owned or inaccessible
WELL_KNOWN_PORTS = {
    53: "DNS Resolver",
    67: "DHCP Client",
    68: "DHCP Client",
    80: "HTTP Web Traffic",
    123: "NTP Time Sync",
    443: "HTTPS Web Traffic",
    5353: "mDNS / Bonjour",
    1900: "UPnP / SSDP",
    22: "SSH Terminal",
    3306: "MySQL Database",
    5432: "PostgreSQL",
    6379: "Redis Cache",
    8080: "HTTP Proxy / Dev",
}


class ProcessTracker:
    """Thread-safe socket-to-process mapper and application bandwidth tracker."""

    def __init__(self, cache_ttl=2.0):
        self.cache_ttl = cache_ttl
        self.lock = threading.Lock()
        self.port_map = {}
        self.last_cache_refresh = 0
        self.app_bytes = Counter()
        self.app_packets = Counter()
        self._psutil_available = True
        try:
            import psutil
            self._psutil = psutil
        except ImportError:
            self._psutil = None
            self._psutil_available = False

    def reset(self):
        """Resets bandwidth counters."""
        with self.lock:
            self.app_bytes.clear()
            self.app_packets.clear()

    def _refresh_port_map(self, now):
        """Scans local sockets to associate open ports with running process names."""
        if not self._psutil_available or self._psutil is None:
            return

        new_map = {}
        try:
            connections = self._psutil.net_connections(kind="inet")
            pid_names = {}

            for conn in connections:
                pid = conn.pid
                if not pid:
                    continue

                if pid not in pid_names:
                    try:
                        proc = self._psutil.Process(pid)
                        name = proc.name()
                        if name.endswith(" (deleted)"):
                            name = name[:-10]
                        pid_names[pid] = name.capitalize()
                    except Exception:
                        pid_names[pid] = None

                pname = pid_names.get(pid)
                if pname and conn.laddr and conn.laddr.port:
                    new_map[conn.laddr.port] = pname

        except Exception:
            pass

        self.port_map = new_map
        self.last_cache_refresh = now

    def resolve_app(self, packet_info):
        """Identifies the application or service associated with a packet."""
        sport = packet_info.get("src_port")
        dport = packet_info.get("dst_port")

        now = time.time()
        if now - self.last_cache_refresh > self.cache_ttl:
            self._refresh_port_map(now)

        # 1. Match local running processes via psutil port map
        if sport and sport in self.port_map:
            return self.port_map[sport]
        if dport and dport in self.port_map:
            return self.port_map[dport]

        # 2. Match well-known network service ports
        if dport and dport in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[dport]
        if sport and sport in WELL_KNOWN_PORTS:
            return WELL_KNOWN_PORTS[sport]

        # 3. Explicit app attribute if already provided (e.g. from simulation)
        if packet_info.get("app") and packet_info.get("app") != "Unknown":
            return packet_info.get("app")

        proto = packet_info.get("protocol", "OTHER")
        if proto == "ICMP":
            return "Ping / ICMP"
        if proto == "ARP":
            return "ARP Discovery"

        return "System / Network"

    def resolve_and_record(self, packet_info):
        """Resolves the application and accumulates its byte and packet count."""
        app_name = self.resolve_app(packet_info)
        size = packet_info.get("size", 0)

        with self.lock:
            self.app_bytes[app_name] += size
            self.app_packets[app_name] += 1

        return app_name

    def get_top_apps(self, limit=5, total_bytes=0):
        """Returns the top applications ranked by bandwidth usage."""
        with self.lock:
            if not self.app_bytes:
                return []

            top = self.app_bytes.most_common(limit)
            result = []
            for name, byte_count in top:
                pkts = self.app_packets.get(name, 0)
                pct = round((byte_count / total_bytes * 100), 1) if total_bytes > 0 else 0
                result.append({
                    "name": name,
                    "bytes": byte_count,
                    "bytes_formatted": human_bytes(byte_count),
                    "packets": pkts,
                    "percentage": min(pct, 100.0),
                })
            return result
