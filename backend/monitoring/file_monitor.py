"""
Auraveil — File Activity Monitor
Tracks file system events (create, modify, delete) using watchdog.
Rapid file modification bursts are a key ransomware signal.
"""

import os
import threading
import time
import logging
from collections import defaultdict
from datetime import datetime

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from backend.config import WATCHED_PATHS

logger = logging.getLogger(__name__)


class _AuraveilFileHandler(FileSystemEventHandler):
    """Internal handler that counts file system events."""

    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self._event_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: {"created": 0, "modified": 0, "deleted": 0, "moved": 0}
        )
        self._total_events = 0

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            with self.lock:
                self._event_counts[event.src_path]["created"] += 1
                self._total_events += 1

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            with self.lock:
                self._event_counts[event.src_path]["modified"] += 1
                self._total_events += 1

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            with self.lock:
                self._event_counts[event.src_path]["deleted"] += 1
                self._total_events += 1

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            with self.lock:
                self._event_counts[event.src_path]["moved"] += 1
                self._total_events += 1

    def flush_counts(self) -> dict:
        """Return and reset accumulated event counts."""
        with self.lock:
            summary = {
                "total_events": self._total_events,
                "by_type": {
                    "created": 0,
                    "modified": 0,
                    "deleted": 0,
                    "moved": 0,
                },
                "files_affected": len(self._event_counts),
            }

            for _path, counts in self._event_counts.items():
                for event_type, count in counts.items():
                    summary["by_type"][event_type] += count

            # Reset
            self._event_counts.clear()
            self._total_events = 0

            return summary


class FileActivityMonitor:
    """
    Tracks file system events using watchdog.
    Call get_activity_summary() each monitoring cycle to get event rates.
    """

    def __init__(self, watch_paths: list[str] | None = None):
        self.watch_paths = watch_paths or WATCHED_PATHS
        self._handler = _AuraveilFileHandler()
        self._observer = Observer()
        self._running = False

    def start(self):
        """Start watching configured paths."""
        if self._running:
            return

        scheduled = 0
        for path in self.watch_paths:
            # Normalize path separators for Windows compatibility
            normalized = os.path.normpath(path)
            if not os.path.isdir(normalized):
                logger.warning(f"Watch path not found, skipping: {normalized}")
                continue
            try:
                self._observer.schedule(self._handler, normalized, recursive=True)
                logger.info(f"Watching: {normalized}")
                scheduled += 1
            except Exception as e:
                logger.warning(f"Failed to watch {normalized}: {e}")

        if scheduled == 0:
            logger.warning("No valid watch paths found. File monitor not started.")
            return

        self._observer.start()
        self._running = True
        logger.info(f"File activity monitor started ({scheduled} paths)")

    def stop(self):
        """Stop file system observer."""
        if self._running:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._running = False
            logger.info("File activity monitor stopped")

    def get_activity_summary(self) -> dict:
        """
        Returns accumulated file events since last call and resets counters.
        
        Returns:
            {
                "timestamp": "ISO-8601",
                "total_events": int,
                "by_type": {"created": int, "modified": int, "deleted": int, "moved": int},
                "files_affected": int,
            }
        """
        summary = self._handler.flush_counts()
        summary["timestamp"] = datetime.now().isoformat()
        return summary

    @property
    def is_running(self) -> bool:
        return self._running
