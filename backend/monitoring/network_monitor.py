"""
Auraveil — Network Monitor
Packet-level network monitoring using Scapy + Npcap.
Gracefully falls back to psutil if Npcap is not available.
"""

import threading
import logging
import psutil
from collections import deque, defaultdict
from datetime import datetime

from backend.config import (
    NETWORK_INTERFACE,
    PACKET_BUFFER_SIZE,
    BPF_FILTER,
    SUSPICIOUS_PORTS,
    NPCAP_FALLBACK,
)

logger = logging.getLogger(__name__)

# Try to import Scapy — it may fail if Npcap is not installed
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, conf

    # Suppress Scapy's verbose output
    conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available. Network monitoring will use psutil fallback.")


class NetworkMonitor:
    """
    Packet-level network monitoring using Scapy + Npcap.

    Falls back to psutil.net_io_counters() if Scapy/Npcap is not available
    and NPCAP_FALLBACK is enabled in config.
    """

    def __init__(self, interface: str | None = NETWORK_INTERFACE):
        self.interface = interface
        self._lock = threading.Lock()
        self._running = False
        self._sniffer_thread: threading.Thread | None = None

        # Packet capture state
        self.packet_buffer: deque = deque(maxlen=PACKET_BUFFER_SIZE)
        self._reset_stats()

        # Detect available mode
        self.scapy_mode = SCAPY_AVAILABLE
        if not self.scapy_mode and not NPCAP_FALLBACK:
            raise RuntimeError(
                "Scapy/Npcap not available and NPCAP_FALLBACK is disabled. "
                "Install Npcap from https://npcap.com/#download"
            )

    def _reset_stats(self):
        """Reset per-cycle statistics."""
        self._stats = {
            "packets_in": 0,
            "packets_out": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "unique_destinations": set(),
            "dns_queries": [],
            "suspicious_ports": [],
            "connections": defaultdict(
                lambda: {"bytes_sent": 0, "bytes_recv": 0, "packets": 0}
            ),
        }

    def start_capture(self):
        """Start packet capture in a background thread."""
        if self._running:
            return

        if not self.scapy_mode:
            logger.info("Network monitor running in psutil fallback mode")
            self._running = True
            return

        self._running = True
        self._sniffer_thread = threading.Thread(
            target=self._capture_loop, daemon=True, name="auraveil-net-capture"
        )
        self._sniffer_thread.start()
        logger.info(
            f"Network capture started on interface: "
            f"{self.interface or 'auto-detect'}"
        )

    def _capture_loop(self):
        """Background thread: continuously sniff packets."""
        try:
            sniff(
                iface=self.interface,
                filter=BPF_FILTER,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            )
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
            self._running = False

    def _process_packet(self, packet):
        """
        Callback for each captured packet.
        - Track connections (TCP SYN/FIN/RST)
        - Count bytes per destination
        - Log DNS queries
        - Flag known-suspicious ports
        """
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        pkt_len = len(packet)

        with self._lock:
            # Determine direction by checking if src is a local address
            local_ips = self._get_local_ips()

            if ip_layer.src in local_ips:
                # Outbound
                self._stats["packets_out"] += 1
                self._stats["bytes_out"] += pkt_len
                self._stats["unique_destinations"].add(ip_layer.dst)
                dest_key = ip_layer.dst
            else:
                # Inbound
                self._stats["packets_in"] += 1
                self._stats["bytes_in"] += pkt_len
                dest_key = ip_layer.src

            # Track connection bytes
            self._stats["connections"][dest_key]["packets"] += 1
            if ip_layer.src in local_ips:
                self._stats["connections"][dest_key]["bytes_sent"] += pkt_len
            else:
                self._stats["connections"][dest_key]["bytes_recv"] += pkt_len

            # Check for suspicious ports
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                for port in (tcp.sport, tcp.dport):
                    if port in SUSPICIOUS_PORTS:
                        self._stats["suspicious_ports"].append(
                            {"port": port, "src": ip_layer.src, "dst": ip_layer.dst}
                        )

            if packet.haslayer(UDP):
                udp = packet[UDP]
                for port in (udp.sport, udp.dport):
                    if port in SUSPICIOUS_PORTS:
                        self._stats["suspicious_ports"].append(
                            {"port": port, "src": ip_layer.src, "dst": ip_layer.dst}
                        )

            # Track DNS queries
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try:
                    qname = packet[DNSQR].qname.decode("utf-8", errors="ignore")
                    qname = qname.rstrip(".")
                    self._stats["dns_queries"].append(qname)
                except Exception:
                    pass

    def stop_capture(self):
        """Stop packet capture."""
        self._running = False
        if self._sniffer_thread and self._sniffer_thread.is_alive():
            self._sniffer_thread.join(timeout=3)
        logger.info("Network capture stopped")

    def get_network_summary(self) -> dict:
        """
        Return network stats since last call and reset counters.
        Falls back to psutil if Scapy is not available.
        """
        if not self.scapy_mode:
            return self._get_psutil_fallback()

        with self._lock:
            summary = {
                "timestamp": datetime.now().isoformat(),
                "packets_in": self._stats["packets_in"],
                "packets_out": self._stats["packets_out"],
                "bytes_in": self._stats["bytes_in"],
                "bytes_out": self._stats["bytes_out"],
                "active_connections": len(self._stats["connections"]),
                "unique_destinations": len(self._stats["unique_destinations"]),
                "dns_queries": list(set(self._stats["dns_queries"]))[:20],
                "suspicious_ports": self._stats["suspicious_ports"][:10],
            }

            self._reset_stats()

        return summary

    def get_per_process_network(self) -> dict[int, dict]:
        """
        Cross-reference psutil.net_connections() to map network activity
        to specific PIDs. This works regardless of Scapy availability.
        """
        process_net = defaultdict(
            lambda: {"connections": 0, "established": 0, "listening": 0}
        )

        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid:
                    process_net[conn.pid]["connections"] += 1
                    if conn.status == "ESTABLISHED":
                        process_net[conn.pid]["established"] += 1
                    elif conn.status == "LISTEN":
                        process_net[conn.pid]["listening"] += 1
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

        return dict(process_net)

    def _get_psutil_fallback(self) -> dict:
        """Fallback: use psutil for basic network stats."""
        net = psutil.net_io_counters()
        connections = psutil.net_connections(kind="inet") if net else []

        return {
            "timestamp": datetime.now().isoformat(),
            "packets_in": net.packets_recv if net else 0,
            "packets_out": net.packets_sent if net else 0,
            "bytes_in": net.bytes_recv if net else 0,
            "bytes_out": net.bytes_sent if net else 0,
            "active_connections": len(
                [c for c in connections if c.status == "ESTABLISHED"]
            ),
            "unique_destinations": 0,
            "dns_queries": [],
            "suspicious_ports": [],
        }

    @staticmethod
    def _get_local_ips() -> set[str]:
        """Get all local IP addresses on this machine."""
        local_ips = {"127.0.0.1", "::1"}
        for iface_addrs in psutil.net_if_addrs().values():
            for addr in iface_addrs:
                if addr.family in (2, 23):  # AF_INET, AF_INET6
                    local_ips.add(addr.address)
        return local_ips

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def mode(self) -> str:
        return "scapy" if self.scapy_mode else "psutil_fallback"
