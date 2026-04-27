"""
Auraveil — Process Tracker (Phase 2)
Tracks process creation, termination, and parent-child relationships.
Detects suspicious spawning patterns (e.g., cmd.exe spawned by word.exe).
"""

import time
import logging
import psutil
from collections import defaultdict
from datetime import datetime

from backend.config import PROCESS_SPAWN_BURST_THRESHOLD

logger = logging.getLogger(__name__)


class ProcessTracker:
    """
    Tracks process lifecycle events and builds a process tree.

    - Detects new process creation and termination
    - Maintains parent-child relationships
    - Flags suspicious spawn patterns (burst spawning, unusual parents)
    """

    # Processes that should NOT spawn command shells
    SUSPICIOUS_PARENTS = {
        "winword.exe", "excel.exe", "powerpnt.exe",  # Office apps
        "acrord32.exe", "foxitreader.exe",             # PDF readers
        "chrome.exe", "firefox.exe", "msedge.exe",     # Browsers
        "notepad.exe", "mspaint.exe",                   # Simple apps
    }

    # Processes commonly spawned by malware
    SUSPICIOUS_CHILDREN = {
        "cmd.exe", "powershell.exe", "pwsh.exe",
        "wscript.exe", "cscript.exe", "mshta.exe",
        "certutil.exe", "bitsadmin.exe", "regsvr32.exe",
    }

    def __init__(self):
        self._known_pids: dict[int, dict] = {}
        self._spawn_counts: dict[int, list[float]] = defaultdict(list)
        self._alerts: list[dict] = []
        self._last_scan_pids: set[int] = set()

    def scan(self) -> dict:
        """
        Scan running processes and detect lifecycle events.

        Returns:
            {
                "new_processes": [...],
                "terminated_processes": [...],
                "suspicious_spawns": [...],
                "process_tree": {pid: {"name": str, "parent_pid": int, ...}, ...}
            }
        """
        current_pids = set()
        current_processes = {}
        new_processes = []
        suspicious_spawns = []

        for proc in psutil.process_iter(["pid", "name", "ppid", "create_time"]):
            try:
                info = proc.info
                pid = info["pid"]
                current_pids.add(pid)

                current_processes[pid] = {
                    "pid": pid,
                    "name": info.get("name", ""),
                    "parent_pid": info.get("ppid", 0),
                    "create_time": info.get("create_time", 0),
                }

                # Detect new process
                if pid not in self._known_pids:
                    new_processes.append(current_processes[pid])

                    # Check for suspicious parent-child relationships
                    parent_name = self._get_process_name(info.get("ppid", 0))
                    child_name = (info.get("name", "") or "").lower()

                    if (
                        parent_name
                        and parent_name.lower() in self.SUSPICIOUS_PARENTS
                        and child_name in self.SUSPICIOUS_CHILDREN
                    ):
                        alert = {
                            "type": "suspicious_spawn",
                            "timestamp": datetime.now().isoformat(),
                            "parent_pid": info.get("ppid", 0),
                            "parent_name": parent_name,
                            "child_pid": pid,
                            "child_name": child_name,
                            "reason": (
                                f"{parent_name} spawned {child_name} — "
                                f"potential malicious macro/exploit"
                            ),
                        }
                        suspicious_spawns.append(alert)
                        self._alerts.append(alert)
                        # Cap alerts list to prevent unbounded memory growth
                        if len(self._alerts) > 1000:
                            self._alerts = self._alerts[-500:]
                        logger.warning(
                            f"Suspicious spawn: {parent_name} (PID {info.get('ppid', 0)}) "
                            f"→ {child_name} (PID {pid})"
                        )

                    # Track spawn burst per parent
                    ppid = info.get("ppid", 0)
                    if ppid:
                        now = time.time()
                        self._spawn_counts[ppid].append(now)
                        # Keep only last 60 seconds
                        self._spawn_counts[ppid] = [
                            t for t in self._spawn_counts[ppid] if now - t < 60
                        ]
                        if len(self._spawn_counts[ppid]) >= PROCESS_SPAWN_BURST_THRESHOLD:
                            parent_name = self._get_process_name(ppid)
                            alert = {
                                "type": "spawn_burst",
                                "timestamp": datetime.now().isoformat(),
                                "parent_pid": ppid,
                                "parent_name": parent_name or "unknown",
                                "children_count": len(self._spawn_counts[ppid]),
                                "reason": (
                                    f"{parent_name or 'PID ' + str(ppid)} spawned "
                                    f"{len(self._spawn_counts[ppid])} processes in 60s"
                                ),
                            }
                            suspicious_spawns.append(alert)
                            self._alerts.append(alert)
                            # Reset to avoid continuous alerting
                            self._spawn_counts[ppid] = []

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Detect terminated processes
        terminated = self._last_scan_pids - current_pids
        terminated_processes = [
            self._known_pids[pid]
            for pid in terminated
            if pid in self._known_pids
        ]

        # Update state
        self._known_pids = current_processes
        self._last_scan_pids = current_pids

        return {
            "new_processes": new_processes,
            "terminated_processes": terminated_processes,
            "suspicious_spawns": suspicious_spawns,
            "total_tracked": len(current_pids),
        }

    def get_process_tree(self) -> dict[int, dict]:
        """Return current process tree for frontend display."""
        return dict(self._known_pids)

    def get_recent_alerts(self, limit: int = 20) -> list[dict]:
        """Get recent process lifecycle alerts."""
        return self._alerts[-limit:]

    def _get_process_name(self, pid: int) -> str | None:
        """Get process name by PID, returns None if not found."""
        if pid in self._known_pids:
            return self._known_pids[pid].get("name")
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
