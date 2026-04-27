"""
Auraveil — Feature Engineering
Transforms raw monitoring metrics into ML-ready feature vectors.
Phase 2: Adds sequence building, network/file features, and entropy.
"""

import math
import numpy as np
from collections import deque

from backend.config import LSTM_WINDOW_SIZE


class FeatureEngineering:
    """Transforms raw metrics into ML-ready feature vectors."""

    # Feature names in order — used for explainability
    FEATURE_NAMES = [
        "cpu_percent",
        "memory_percent",
        "num_threads",
        "io_read_bytes",
        "io_write_bytes",
        "io_read_count",
        "io_write_count",
    ]

    @staticmethod
    def extract_process_features(process_data: dict) -> np.ndarray:
        """
        Extract a feature vector from a single process snapshot.

        Args:
            process_data: Dict with process metrics from SystemMonitor.

        Returns:
            1-D numpy array of shape (7,).
        """
        io = process_data.get("io_counters", {})

        return np.array(
            [
                process_data.get("cpu_percent", 0.0),
                process_data.get("memory_percent", 0.0),
                process_data.get("num_threads", 1),
                io.get("read_bytes", 0),
                io.get("write_bytes", 0),
                io.get("read_count", 0),
                io.get("write_count", 0),
            ],
            dtype=np.float64,
        )

    @staticmethod
    def compute_rate_of_change(
        current: dict, previous: dict
    ) -> dict[str, float]:
        """
        Compute delta (rate of change) between two consecutive process snapshots.
        Useful for detecting sudden spikes.

        Returns:
            Dict with delta values for key metrics.
        """
        cur_io = current.get("io_counters", {})
        prev_io = previous.get("io_counters", {})

        return {
            "cpu_delta": current.get("cpu_percent", 0) - previous.get("cpu_percent", 0),
            "memory_delta": current.get("memory_percent", 0) - previous.get("memory_percent", 0),
            "thread_delta": current.get("num_threads", 0) - previous.get("num_threads", 0),
            "read_bytes_delta": cur_io.get("read_bytes", 0) - prev_io.get("read_bytes", 0),
            "write_bytes_delta": cur_io.get("write_bytes", 0) - prev_io.get("write_bytes", 0),
        }

    @staticmethod
    def compute_rolling_stats(
        buffer: deque | list, window: int = 60
    ) -> dict[str, dict[str, float]]:
        """
        Compute mean, std, max over a sliding window of system snapshots.

        Args:
            buffer: List of metric snapshots from SystemMonitor.buffer.
            window: Number of most recent snapshots to analyze.

        Returns:
            {
                "cpu_percent": {"mean": float, "std": float, "max": float},
                "memory_percent": {"mean": float, "std": float, "max": float},
                ...
            }
        """
        recent = list(buffer)[-window:]

        if not recent:
            return {}

        metrics = {
            "cpu_percent": [],
            "memory_percent": [],
        }

        for snapshot in recent:
            system = snapshot.get("system", {})
            metrics["cpu_percent"].append(system.get("cpu_percent", 0))
            metrics["memory_percent"].append(system.get("memory_percent", 0))

        result = {}
        for metric_name, values in metrics.items():
            arr = np.array(values)
            result[metric_name] = {
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr)),
                "max": float(np.max(arr)),
                "min": float(np.min(arr)),
            }

        return result

    @staticmethod
    def batch_extract_features(process_list: list[dict]) -> np.ndarray:
        """
        Extract features from a list of process snapshots.

        Args:
            process_list: List of process dicts.

        Returns:
            2-D numpy array of shape (n_processes, 7).
        """
        if not process_list:
            return np.empty((0, len(FeatureEngineering.FEATURE_NAMES)))

        features = [
            FeatureEngineering.extract_process_features(p)
            for p in process_list
        ]

        return np.vstack(features)

    # ─── Phase 2: Sequence Building ──────────────────────────────────────────

    @staticmethod
    def build_sequences(
        feature_history: list[np.ndarray],
        window_size: int = LSTM_WINDOW_SIZE,
    ) -> list[np.ndarray]:
        """
        Build sliding-window sequences from a list of per-timestep feature vectors.

        Args:
            feature_history: List of 1-D feature arrays (one per timestep).
            window_size: Number of timesteps per sequence.

        Returns:
            List of 2-D arrays, each of shape (window_size, n_features).
        """
        if len(feature_history) < window_size:
            return []

        sequences = []
        for i in range(len(feature_history) - window_size + 1):
            window = np.stack(feature_history[i : i + window_size])
            sequences.append(window)

        return sequences

    @staticmethod
    def compute_file_activity_features(file_activity: dict) -> dict[str, float]:
        """
        Extract ML features from file activity summary.

        Args:
            file_activity: Dict from FileActivityMonitor.get_activity_summary().

        Returns:
            Dict with file-derived features.
        """
        by_type = file_activity.get("by_type", {})
        total = file_activity.get("total_events", 0)

        return {
            "file_total_events": total,
            "file_created": by_type.get("created", 0),
            "file_modified": by_type.get("modified", 0),
            "file_deleted": by_type.get("deleted", 0),
            "file_moved": by_type.get("moved", 0),
            "file_files_affected": file_activity.get("files_affected", 0),
        }

    @staticmethod
    def compute_network_features(network_summary: dict) -> dict[str, float]:
        """
        Extract ML features from network activity summary.

        Args:
            network_summary: Dict from NetworkMonitor.get_network_summary().

        Returns:
            Dict with network-derived features.
        """
        return {
            "net_packets_in": network_summary.get("packets_in", 0),
            "net_packets_out": network_summary.get("packets_out", 0),
            "net_bytes_in": network_summary.get("bytes_in", 0),
            "net_bytes_out": network_summary.get("bytes_out", 0),
            "net_active_connections": network_summary.get("active_connections", 0),
            "net_unique_destinations": network_summary.get("unique_destinations", 0),
            "net_suspicious_ports": len(network_summary.get("suspicious_ports", [])),
            "net_dns_queries": len(network_summary.get("dns_queries", [])),
        }

    @staticmethod
    def compute_entropy(event_counts: dict[str, int]) -> float:
        """
        Compute Shannon entropy of event type distribution.
        High entropy = diverse activity (normal), low entropy = focused
        activity (potential attack pattern like ransomware doing only writes).

        Args:
            event_counts: Dict like {"created": 5, "modified": 100, "deleted": 2}

        Returns:
            Shannon entropy value (0 = single type, higher = more diverse).
        """
        total = sum(event_counts.values())
        if total == 0:
            return 0.0

        entropy = 0.0
        for count in event_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return entropy
