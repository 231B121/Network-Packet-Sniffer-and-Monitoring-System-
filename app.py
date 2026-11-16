"""Network Packet Sniffer & Traffic Monitoring System - Flask Web Backend.

This module provides the REST API endpoints and web server for the interactive
packet sniffer dashboard. It coordinates the background Sniffer thread and the
TrafficMonitor data collector.

Key Endpoints:
  - GET  /                  : Serves the Web Dashboard UI
  - GET  /api/interfaces    : Lists available network interfaces (eth0, wlan0, lo)
  - GET  /api/stats         : Real-time traffic statistics (counts, protocols, speed)
  - GET  /api/packets       : Recent packet stream with protocol and search filters
  - GET  /api/packet/<id>   : Detailed packet inspection (headers, layers, payload hex)
  - POST /api/start         : Starts packet capture (Live raw socket or Simulated Demo)
  - POST /api/stop          : Stops the active packet capture
  - POST /api/clear         : Resets packet history and traffic metrics
  - GET  /api/export/pcap   : Downloads capture as a Wireshark-compatible PCAP file
  - GET  /api/export/json   : Downloads capture as a JSON file
"""
import io
import json
import os
import sys
import tempfile
import time
from flask import Flask, jsonify, make_response, render_template, request, send_file

from monitor import TrafficMonitor
from sniffer import Sniffer


def is_admin():
    """Checks whether the application is running with root or administrator privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())


# Initialize Flask web application
app = Flask(__name__)

# Initialize central traffic monitor and packet sniffer
monitor = TrafficMonitor(keep=1500)
active_sniffer = Sniffer(monitor=monitor)

# Active configuration state
active_config = {
    "iface": None,
    "filter": None,
    "simulated": False,
}


@app.route("/")
def index():
    """Renders the main student dashboard UI."""
    resp = make_response(render_template("dashboard.html"))
    # Disable caching so dashboard updates immediately during development
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """Returns available network interfaces and user privilege status."""
    ifaces = []
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
    except Exception:
        # Fallback to standard interface names
        ifaces = ["lo", "eth0", "wlan0"]

    return jsonify({
        "interfaces": ifaces,
        "is_admin": is_admin(),
        "default_iface": ifaces[0] if ifaces else "lo",
    })


@app.route("/api/status", methods=["GET"])
@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Returns real-time aggregated metrics, protocol distribution, and alerts."""
    running = active_sniffer.is_running()
    stats_data = monitor.stats(is_running=running)
    stats_data["mode"] = "simulated" if active_config["simulated"] else "live"
    stats_data["iface"] = active_config["iface"] or "default"
    stats_data["filter"] = active_config["filter"] or ""
    stats_data["is_admin"] = is_admin()

    err = active_sniffer.get_error()
    if err:
        stats_data["error"] = err

    return jsonify(stats_data)


@app.route("/api/start", methods=["POST"])
def start_capture():
    """Starts packet sniffing session (live raw socket or simulation)."""
    data = request.get_json(silent=True) or {}
    iface = data.get("iface") or None
    bpf = data.get("filter") or None
    simulated = bool(data.get("simulated", False))

    # If already running with identical settings, keep running
    if (
        active_sniffer.is_running()
        and active_config.get("simulated") == simulated
        and active_config.get("iface") == iface
    ):
        return jsonify({"status": "already_running", "running": True})

    # If already running with different settings, stop first
    if active_sniffer.is_running():
        active_sniffer.stop()

    # Automatically fallback to simulation if non-root user doesn't have raw socket access
    if not is_admin() and not simulated:
        if data.get("auto_fallback", True):
            simulated = True

    active_config["iface"] = iface
    active_config["filter"] = bpf
    active_config["simulated"] = simulated

    success = active_sniffer.start(
        iface=iface,
        bpf=bpf,
        simulated=simulated,
    )

    if not success:
        err = active_sniffer.get_error() or "Could not start packet sniffer."
        return jsonify({"error": err, "running": False}), 400

    # Brief delay to catch instant initialization errors (e.g. invalid BPF syntax)
    time.sleep(0.08)
    if not active_sniffer.is_running() and active_sniffer.get_error():
        err = active_sniffer.get_error()
        return jsonify({"error": err, "running": False}), 400

    return jsonify({
        "status": "started",
        "running": True,
        "mode": "simulated" if simulated else "live",
        "iface": iface or "auto",
        "filter": bpf or "",
    })


@app.route("/api/stop", methods=["POST"])
def stop_capture():
    """Stops the active packet sniffing session."""
    active_sniffer.stop()
    return jsonify({"status": "stopped", "running": False})


@app.route("/api/clear", methods=["POST"])
def clear_capture():
    """Clears all accumulated statistics and captured packets."""
    monitor.reset()
    active_sniffer.captured_packets.clear()
    return jsonify({"status": "cleared"})


@app.route("/api/packets", methods=["GET"])
def get_packets():
    """Returns recent packets filtered by protocol or search query."""
    limit = request.args.get("limit", 50, type=int)
    limit = max(1, min(limit, 500))
    protocol = request.args.get("protocol", "ALL")
    search = request.args.get("search", "")

    packets = monitor.latest(n=limit, protocol=protocol, search=search)
    return jsonify(packets)


@app.route("/api/packet/<int:packet_id>", methods=["GET"])
def get_packet_detail(packet_id):
    """Returns deep inspection details for a specific packet (headers, layers, payload)."""
    pkt = monitor.get_packet(packet_id)
    if not pkt:
        return jsonify({"error": "Packet not found"}), 404
    return jsonify(pkt)


@app.route("/api/export/json", methods=["GET"])
def export_json():
    """Exports all captured packets as a JSON file download."""
    packets = monitor.get_all_packets()
    output = json.dumps(packets, indent=2)
    bio = io.BytesIO(output.encode("utf-8"))
    return send_file(
        bio,
        mimetype="application/json",
        as_attachment=True,
        download_name="packet_capture.json",
    )


@app.route("/api/export/pcap", methods=["GET"])
def export_pcap():
    """Generates and downloads a Wireshark-compatible PCAP file from captured packets."""
    from scapy.all import IP, TCP, UDP, ICMP, Ether, wrpcap

    packets = monitor.get_all_packets()
    scapy_pkts = []

    for p in packets:
        try:
            eth = Ether(
                src=p.get("src_mac", "00:00:00:00:00:00").lower(),
                dst=p.get("dst_mac", "00:00:00:00:00:00").lower(),
            )
            src_ip = p.get("src_ip")
            dst_ip = p.get("dst_ip")
            if not src_ip or src_ip == "-" or not dst_ip or dst_ip == "-":
                continue

            ip = IP(src=src_ip, dst=dst_ip)
            proto = p.get("protocol")
            l4 = None

            if proto == "TCP":
                flags_val = 0
                for f in p.get("flags", []):
                    if f == "SYN":
                        flags_val |= 0x02
                    elif f == "ACK":
                        flags_val |= 0x10
                    elif f == "FIN":
                        flags_val |= 0x01
                    elif f == "RST":
                        flags_val |= 0x04
                    elif f == "PSH":
                        flags_val |= 0x08
                l4 = TCP(
                    sport=p.get("src_port") or 80,
                    dport=p.get("dst_port") or 80,
                    flags=flags_val if flags_val else 2,
                )
            elif proto == "UDP":
                l4 = UDP(
                    sport=p.get("src_port") or 53,
                    dport=p.get("dst_port") or 53,
                )
            elif proto == "ICMP":
                l4 = ICMP(type=p.get("icmp_type", 8), code=p.get("icmp_code", 0))

            if l4:
                scapy_pkts.append(eth / ip / l4)
        except Exception:
            continue

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_name = tmp.name

    if scapy_pkts:
        wrpcap(tmp_name, scapy_pkts)
    else:
        # Write empty pcap header if no packets
        wrpcap(tmp_name, [])

    return send_file(
        tmp_name,
        mimetype="application/vnd.tcpdump.pcap",
        as_attachment=True,
        download_name="network_traffic.pcap",
    )


def run(host="0.0.0.0", port=5000, debug=False):
    """Starts the Flask web application."""
    print("=" * 65)
    print(" 🌐 PACKET SNIFFER & TRAFFIC MONITOR DASHBOARD")
    print(f" 🚀 Web URL:        http://127.0.0.1:{port}")
    print(f" 🛡️  Mode:          {'Root (Live Network Capture)' if is_admin() else 'Standard User (Demo Simulation)'}")
    print("=" * 65)
    print(" Open the Web URL in your browser to view the live dashboard.")
    print(" Press Ctrl+C in terminal to stop the server.")
    print("=" * 65)
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    port = 5000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run(port=port)
