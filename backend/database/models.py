"""
Auraveil — Database Layer
SQLite schema and helper functions for threat logs, whitelists, and baselines.
All functions use context managers to guarantee connection cleanup.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta
from contextlib import contextmanager

from backend.config import DB_PATH, DATA_DIR


@contextmanager
def _get_connection():
    """Get a SQLite connection as a context manager with auto-commit."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables if they don't exist."""
    with _get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS threats (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT NOT NULL,
                process_name TEXT NOT NULL,
                pid          INTEGER,
                threat_score INTEGER CHECK(threat_score BETWEEN 0 AND 100),
                risk_level   TEXT CHECK(risk_level IN ('safe', 'suspicious', 'malicious')),
                reasons      TEXT,
                action_taken TEXT,
                resolved     BOOLEAN DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS whitelist (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                process_name TEXT UNIQUE NOT NULL,
                hash         TEXT,
                added_at     TEXT NOT NULL,
                reason       TEXT
            );

            CREATE TABLE IF NOT EXISTS system_baseline (
                metric_name  TEXT PRIMARY KEY,
                mean_value   REAL,
                std_value    REAL,
                min_value    REAL,
                max_value    REAL,
                sample_count INTEGER,
                last_updated TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
            CREATE INDEX IF NOT EXISTS idx_threats_risk ON threats(risk_level);
        """)


def log_threat(
    process_name: str,
    pid: int,
    score: int,
    level: str,
    reasons: list[str],
    action: str,
) -> int:
    """Insert a threat record and return the new row ID."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO threats (timestamp, process_name, pid, threat_score,
                                 risk_level, reasons, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().isoformat(),
                process_name,
                pid,
                score,
                level,
                json.dumps(reasons),
                action,
            ),
        )
        return cursor.lastrowid


def get_threat_history(
    days: int = 7, risk_level: str | None = None
) -> list[dict]:
    """Query threat history with optional filters."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        if risk_level:
            cursor.execute(
                """
                SELECT * FROM threats
                WHERE timestamp >= ? AND risk_level = ?
                ORDER BY timestamp DESC
                """,
                (cutoff, risk_level),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM threats
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                """,
                (cutoff,),
            )

        rows = cursor.fetchall()

    results = []
    for row in rows:
        record = dict(row)
        record["reasons"] = json.loads(record["reasons"]) if record["reasons"] else []
        results.append(record)

    return results


def get_active_threats() -> list[dict]:
    """Get unresolved threats."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM threats
            WHERE resolved = 0
            ORDER BY threat_score DESC
            """
        )
        rows = cursor.fetchall()

    results = []
    for row in rows:
        record = dict(row)
        record["reasons"] = json.loads(record["reasons"]) if record["reasons"] else []
        results.append(record)

    return results


def resolve_threat(threat_id: int) -> bool:
    """Mark a threat as resolved. Returns True if the row existed."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE threats SET resolved = 1 WHERE id = ?", (threat_id,)
        )
        return cursor.rowcount > 0


def add_to_whitelist(process_name: str, reason: str = "User approved") -> bool:
    """Add a process to the whitelist. Returns False if already whitelisted."""
    try:
        with _get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO whitelist (process_name, added_at, reason)
                VALUES (?, ?, ?)
                """,
                (process_name, datetime.now().isoformat(), reason),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def remove_from_whitelist(process_name: str) -> bool:
    """Remove a process from whitelist. Returns True if it existed."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM whitelist WHERE process_name = ?", (process_name,)
        )
        return cursor.rowcount > 0


def get_whitelist() -> list[dict]:
    """Get all whitelisted processes."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM whitelist ORDER BY process_name")
        rows = cursor.fetchall()
    return [dict(row) for row in rows]


def is_whitelisted(process_name: str) -> bool:
    """Check if a process is on the whitelist."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM whitelist WHERE process_name = ?", (process_name,)
        )
        return cursor.fetchone() is not None


def update_baseline(
    metric_name: str,
    mean: float,
    std: float,
    min_val: float = 0.0,
    max_val: float = 0.0,
    sample_count: int = 0,
):
    """Update or insert baseline statistics."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO system_baseline
                (metric_name, mean_value, std_value, min_value, max_value,
                 sample_count, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(metric_name) DO UPDATE SET
                mean_value = excluded.mean_value,
                std_value = excluded.std_value,
                min_value = excluded.min_value,
                max_value = excluded.max_value,
                sample_count = excluded.sample_count,
                last_updated = excluded.last_updated
            """,
            (metric_name, mean, std, min_val, max_val, sample_count,
             datetime.now().isoformat()),
        )


def get_baseline() -> dict[str, dict]:
    """Get all baseline statistics as a dict keyed by metric name."""
    with _get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM system_baseline")
        rows = cursor.fetchall()
    return {row["metric_name"]: dict(row) for row in rows}
