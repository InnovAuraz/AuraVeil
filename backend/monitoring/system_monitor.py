"""
Auraveil — System Monitor
Collects real-time system-wide and per-process metrics using psutil.
"""

import psutil
from collections import deque
from datetime import datetime

from backend.config import BUFFER_SIZE


class SystemMonitor:
    """Collects real-time system and per-process metrics."""

    def __init__(self, buffer_size: int = BUFFER_SIZE):
        self.buffer: deque[dict] = deque(maxlen=buffer_size)
        # Prime the first CPU read (psutil needs two calls for meaningful %)
        psutil.cpu_percent(interval=None)

    def collect_metrics(self) -> dict:
        """
        Collect a snapshot of system-wide and per-process metrics.
        Appends the snapshot to the rolling buffer and returns it.
        """
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "system": self._collect_system_metrics(),
            "processes": self._collect_process_metrics(),
        }

        self.buffer.append(snapshot)
        return snapshot

    def _collect_system_metrics(self) -> dict:
        """Collect system-wide CPU, memory, disk, and network stats."""
        disk_io = psutil.disk_io_counters()
        net_io = psutil.net_io_counters()

        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_io": {
                "read_bytes": disk_io.read_bytes if disk_io else 0,
                "write_bytes": disk_io.write_bytes if disk_io else 0,
                "read_count": disk_io.read_count if disk_io else 0,
                "write_count": disk_io.write_count if disk_io else 0,
            },
            "net_io": {
                "bytes_sent": net_io.bytes_sent if net_io else 0,
                "bytes_recv": net_io.bytes_recv if net_io else 0,
                "packets_sent": net_io.packets_sent if net_io else 0,
                "packets_recv": net_io.packets_recv if net_io else 0,
            },
        }

    def _collect_process_metrics(self) -> list[dict]:
        """Collect per-process metrics. Skips inaccessible processes."""
        processes = []

        for proc in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_percent", "num_threads"]
        ):
            try:
                pinfo = proc.info.copy()

                # Get I/O counters (may fail for system processes)
                try:
                    io = proc.io_counters()
                    pinfo["io_counters"] = {
                        "read_bytes": io.read_bytes,
                        "write_bytes": io.write_bytes,
                        "read_count": io.read_count,
                        "write_count": io.write_count,
                    }
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pinfo["io_counters"] = {
                        "read_bytes": 0,
                        "write_bytes": 0,
                        "read_count": 0,
                        "write_count": 0,
                    }

                processes.append(pinfo)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return processes

    def get_buffer(self) -> list[dict]:
        """Return the full rolling buffer as a list (oldest first)."""
        return list(self.buffer)

    def get_buffer_size(self) -> int:
        """Return the current number of snapshots in the buffer."""
        return len(self.buffer)
