"""Traffic Monitor and Metrics Aggregator.

This module collects captured packets in a thread-safe manner, calculates
bandwidth statistics, generates protocol distribution summaries, tracks throughput
(packets/sec, bytes/sec), separates Upload (Outgoing) vs Download (Incoming) traffic,
and detects simple anomalies (e.g., port scans).
"""
import threading
import time
from collections import Counter, defaultdict, deque

from process_tracker import ProcessTracker


def human_bytes(num):
    """Formats raw byte counts into human-readable strings (e.g., KB, MB, GB)."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} TB"


class TrafficMonitor:
    """Thread-safe statistics accumulator for real-time network traffic analysis."""

    def __init__(self, keep=1000, scan_ports=15, scan_window=10):
        """Initializes monitor buffers, thresholds, and locks."""
        self.keep = keep
        self.scan_ports = scan_ports
        self.scan_window = scan_window
        self.lock = threading.Lock()
        self.packet_counter = 0
        self.process_tracker = ProcessTracker()
        self.reset()

    def reset(self):
        """Clears all accumulated metrics and captured packet history."""
        with self.lock:
            self.packets = deque(maxlen=self.keep)
            self.packet_map = {}
            self.protocols = Counter()
            self.talkers = Counter()
            self.ports = Counter()
            self.total = 0
            self.total_bytes = 0

            # Traffic direction tracking (Download vs Upload)
            self.incoming_bytes = 0
            self.incoming_packets = 0
            self.outgoing_bytes = 0
            self.outgoing_packets = 0
            self.local_packets = 0

            self.recent = deque()              # Stores (timestamp, packet_size) for velocity
            self.probes = defaultdict(deque)   # src_ip -> deque of (timestamp, dst_port)
            self.alerted = set()
            self.alerts = []
            self.rate_history = deque(maxlen=30)  # Stores snapshots for timeline velocity chart
            self.last_history_tick = 0
            self.started = time.time()
            if hasattr(self, "process_tracker") and self.process_tracker:
                self.process_tracker.reset()

    def add(self, info):
        """Adds a newly parsed packet into the monitor buffers."""
        now = time.time()
        with self.lock:
            self.packet_counter += 1
            info_copy = dict(info)
            if "id" not in info_copy:
                info_copy["id"] = self.packet_counter

            size = info_copy.get("size", 0)
            proto = info_copy.get("protocol", "OTHER")
            src_ip = info_copy.get("src_ip")
            dst_port = info_copy.get("dst_port")
            direction = info_copy.get("direction", "local")

            # Update core counters
            self.total += 1
            self.total_bytes += size
            self.protocols[proto] += 1

            # Flow direction accumulation
            if direction == "incoming":
                self.incoming_bytes += size
                self.incoming_packets += 1
            elif direction == "outgoing":
                self.outgoing_bytes += size
                self.outgoing_packets += 1
            else:
                self.local_packets += 1

            if src_ip and src_ip != "-":
                self.talkers[src_ip] += 1
            if dst_port is not None:
                self.ports[dst_port] += 1

            # Map active application or service
            app_name = self.process_tracker.resolve_and_record(info_copy)
            info_copy["app"] = app_name

            # Store in rolling buffer
            self.packets.append(info_copy)
            self.packet_map[info_copy["id"]] = info_copy

            # Prevent packet_map dictionary from growing unbounded
            if len(self.packet_map) > self.keep * 1.5:
                current_ids = {p["id"] for p in self.packets}
                self.packet_map = {k: v for k, v in self.packet_map.items() if k in current_ids}

            # Sliding window of packets in the last 10 seconds for velocity
            self.recent.append((now, size))
            while self.recent and now - self.recent[0][0] > 10:
                self.recent.popleft()

            # Record a snapshot of traffic rate once every second for the chart
            if now - self.last_history_tick >= 1.0:
                span = min(10, max(now - self.started, 1))
                cur_pps = round(len(self.recent) / span, 1)
                cur_bps = round(sum(s for _, s in self.recent) / span)
                t_label = time.strftime("%H:%M:%S", time.localtime(now))
                self.rate_history.append({"time": t_label, "pps": cur_pps, "bps": cur_bps})
                self.last_history_tick = now

            # Check for suspicious port scan activity
            self._detect_scan(info_copy, now)

    def _detect_scan(self, info, now):
        """Detects if an IP is scanning multiple distinct ports within a time window."""
        src = info.get("src_ip")
        dport = info.get("dst_port")
        proto = info.get("protocol")

        if proto not in ("TCP", "UDP") or not src or src == "-" or dport is None:
            return

        q = self.probes[src]
        q.append((now, dport))
        while q and now - q[0][0] > self.scan_window:
            q.popleft()

        distinct = len({p for _, p in q})
        if distinct >= self.scan_ports and src not in self.alerted:
            self.alerted.add(src)
            alert_entry = {
                "time": info.get("time", time.strftime("%Y-%m-%d %H:%M:%S")),
                "type": "Possible Port Scan",
                "severity": "high",
                "src_ip": src,
                "detail": f"{distinct} unique ports probed within {self.scan_window}s",
            }
            self.alerts.append(alert_entry)

    def stats(self, is_running=False):
        """Returns a snapshot dictionary of aggregated metrics for the dashboard."""
        with self.lock:
            now = time.time()
            span = min(10, max(now - self.started, 1))
            pps = round(len(self.recent) / span, 1)
            bps = round(sum(s for _, s in self.recent) / span)

            total = self.total
            proto_dict = dict(self.protocols)
            proto_pct = {}
            for p, count in proto_dict.items():
                proto_pct[p] = round((count / total) * 100, 1) if total > 0 else 0

            return {
                "running": is_running,
                "uptime_seconds": int(now - self.started),
                "total": total,
                "bytes": self.total_bytes,
                "bytes_formatted": human_bytes(self.total_bytes),
                "incoming_bytes": self.incoming_bytes,
                "incoming_bytes_formatted": human_bytes(self.incoming_bytes),
                "incoming_packets": self.incoming_packets,
                "outgoing_bytes": self.outgoing_bytes,
                "outgoing_bytes_formatted": human_bytes(self.outgoing_bytes),
                "outgoing_packets": self.outgoing_packets,
                "local_packets": self.local_packets,
                "protocols": proto_dict,
                "protocol_percentages": proto_pct,
                "top_talkers": self.talkers.most_common(5),
                "top_ports": self.ports.most_common(5),
                "top_apps": self.process_tracker.get_top_apps(limit=6, total_bytes=self.total_bytes),
                "pps": pps,
                "bps": bps,
                "bps_formatted": human_bytes(bps) + "/s",
                "alerts": list(self.alerts[-15:]),
                "rate_history": list(self.rate_history),
            }

    def latest(self, n=50, protocol=None, search=None):
        """Returns recent packets matching optional protocol and search filters."""
        with self.lock:
            packets_list = list(self.packets)

        # Reverse to show newest packets at the top
        res = packets_list[::-1]

        if protocol and protocol.upper() != "ALL":
            res = [p for p in res if p.get("protocol", "").upper() == protocol.upper()]

        if search:
            query = search.strip().lower()
            res = [
                p for p in res
                if query in str(p.get("src_ip", "")).lower()
                or query in str(p.get("dst_ip", "")).lower()
                or query in str(p.get("src_entity", "")).lower()
                or query in str(p.get("dst_entity", "")).lower()
                or query in str(p.get("src_port", "")).lower()
                or query in str(p.get("dst_port", "")).lower()
                or query in str(p.get("summary", "")).lower()
                or query in str(p.get("flow_summary", "")).lower()
                or query in str(p.get("direction_label", "")).lower()
                or query in str(p.get("app", "")).lower()
            ]

        return res[:n]

    def get_packet(self, packet_id):
        """Returns full packet details for a single packet by its ID."""
        with self.lock:
            return self.packet_map.get(packet_id)

    def get_all_packets(self):
        """Returns a snapshot list of all currently stored packets."""
        with self.lock:
            return list(self.packets)


def format_summary(s):
    """Formats text summary for console / CLI display."""
    total = s.get("total", 0)
    bytes_count = s.get("bytes", 0)
    lines = [
        "=" * 60,
        "📊 NETWORK TRAFFIC CAPTURE SUMMARY",
        "=" * 60,
        f"Total Packets:     {total:<10}",
        f"Data Transferred:  {human_bytes(bytes_count)} ({bytes_count} bytes)",
        f"  • Download (In): {s.get('incoming_bytes_formatted', '0 B')} ({s.get('incoming_packets', 0)} pkts)",
        f"  • Upload (Out):   {s.get('outgoing_bytes_formatted', '0 B')} ({s.get('outgoing_packets', 0)} pkts)",
        "",
        "Protocol Breakdown:",
    ]

    protocols = s.get("protocols", {})
    if protocols:
        for proto, count in sorted(protocols.items(), key=lambda x: -x[1]):
            pct = (100 * count / total) if total else 0
            lines.append(f"  • {proto:<10}: {count:>6} packets ({pct:5.1f}%)")
    else:
        lines.append("  No packets captured.")

    top_talkers = s.get("top_talkers", [])
    if top_talkers:
        lines.append("\nTop Source Entities:")
        for ip, count in top_talkers:
            lines.append(f"  • {ip:<20} {count:>6} packets")

    alerts = s.get("alerts", [])
    if alerts:
        lines.append("\nSecurity Alerts Detected:")
        for a in alerts:
            lines.append(f"  [!] {a.get('type')} from {a.get('src_ip')} ({a.get('detail')})")

    lines.append("=" * 60)
    return "\n".join(lines)
