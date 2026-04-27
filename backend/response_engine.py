"""
Auraveil — Response Engine (Phase 2)
Central coordinator for threat response: alerts, auto-stop, deduplication.
"""

import time
import logging
import psutil
from datetime import datetime

from backend.config import (
    AUTO_STOP_ENABLED,
    AUTO_STOP_THRESHOLD,
    ALERT_COOLDOWN_SECONDS,
)
from backend.database.models import log_threat, is_whitelisted

logger = logging.getLogger(__name__)


class ResponseEngine:
    """
    Decides what action to take when a threat is detected.

    - Generates alerts with severity levels
    - Optionally auto-stops (kills) processes above AUTO_STOP_THRESHOLD
    - Deduplicates: won't re-alert the same process within cooldown window
    - Respects whitelist
    """

    def __init__(self):
        # {process_name: last_alert_timestamp}
        self._alert_cooldowns: dict[str, float] = {}
        self._kill_log: list[dict] = []

    def evaluate(
        self,
        process_name: str,
        pid: int,
        threat_score: int,
        risk_level: str,
        reasons: list[str],
    ) -> dict:
        """
        Evaluate a threat and decide on the response action.

        Args:
            process_name: Name of the process.
            pid: Process ID.
            threat_score: 0–100 score.
            risk_level: "safe", "suspicious", or "malicious".
            reasons: List of human-readable reason strings.

        Returns:
            {
                "action": "none" | "alerted" | "auto_stopped",
                "alert": {...} | None,
                "suppressed": bool,
                "reason": str
            }
        """
        # Skip safe processes
        if risk_level == "safe":
            return {
                "action": "none",
                "alert": None,
                "suppressed": False,
                "reason": "Score below threshold",
            }

        # Check whitelist
        if is_whitelisted(process_name):
            return {
                "action": "none",
                "alert": None,
                "suppressed": True,
                "reason": f"{process_name} is whitelisted",
            }

        # Check cooldown (deduplication)
        now = time.time()
        last_alert = self._alert_cooldowns.get(process_name, 0)
        if now - last_alert < ALERT_COOLDOWN_SECONDS:
            return {
                "action": "none",
                "alert": None,
                "suppressed": True,
                "reason": f"Cooldown active ({int(ALERT_COOLDOWN_SECONDS - (now - last_alert))}s remaining)",
            }

        # Build alert
        alert = {
            "timestamp": datetime.now().isoformat(),
            "process_name": process_name,
            "pid": pid,
            "threat_score": threat_score,
            "risk_level": risk_level,
            "reasons": reasons,
            "action": "alerted",
        }

        # Decide on action
        action = "alerted"

        if (
            risk_level == "malicious"
            and AUTO_STOP_ENABLED
            and threat_score >= AUTO_STOP_THRESHOLD
        ):
            # Attempt to terminate the process
            killed = self._kill_process(pid, process_name)
            if killed:
                action = "auto_stopped"
                alert["action"] = "auto_stopped"
                logger.warning(
                    f"AUTO-STOPPED: {process_name} (PID {pid}) — "
                    f"score {threat_score}, reasons: {reasons}"
                )

        # Log to database
        log_threat(
            process_name=process_name,
            pid=pid,
            score=threat_score,
            level=risk_level,
            reasons=reasons,
            action=action,
        )

        # Update cooldown
        self._alert_cooldowns[process_name] = now

        logger.info(
            f"Threat response: {action} — {process_name} (PID {pid}), "
            f"score {threat_score}, level {risk_level}"
        )

        return {
            "action": action,
            "alert": alert,
            "suppressed": False,
            "reason": f"Threat detected: {risk_level}",
        }

    def _kill_process(self, pid: int, process_name: str) -> bool:
        """
        Terminate a process by PID.
        Uses SIGTERM first, then SIGKILL after timeout.

        Returns True if process was successfully terminated.
        """
        try:
            proc = psutil.Process(pid)

            # Verify the process name still matches (avoid killing wrong PID)
            if proc.name().lower() != process_name.lower():
                logger.warning(
                    f"PID {pid} name mismatch: expected {process_name}, "
                    f"got {proc.name()}. Aborting kill."
                )
                return False

            # Don't kill system-critical processes
            if pid in (0, 4) or process_name.lower() in (
                "system", "smss.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsass.exe", "svchost.exe",
            ):
                logger.warning(f"Refusing to kill system process: {process_name} (PID {pid})")
                return False

            # Terminate gracefully
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                # Force kill
                proc.kill()
                proc.wait(timeout=2)

            self._kill_log.append({
                "timestamp": datetime.now().isoformat(),
                "pid": pid,
                "process_name": process_name,
                "success": True,
            })

            return True

        except psutil.NoSuchProcess:
            logger.info(f"Process {process_name} (PID {pid}) already gone")
            return False
        except psutil.AccessDenied:
            logger.error(
                f"Access denied killing {process_name} (PID {pid}). "
                f"Run Auraveil as Administrator."
            )
            self._kill_log.append({
                "timestamp": datetime.now().isoformat(),
                "pid": pid,
                "process_name": process_name,
                "success": False,
                "error": "Access denied",
            })
            return False
        except Exception as e:
            logger.error(f"Failed to kill {process_name} (PID {pid}): {e}")
            return False

    def manual_kill(self, pid: int) -> dict:
        """
        Manually kill a process by PID (called from API endpoint).
        No whitelist or threshold checks — user explicitly requested it.

        Returns:
            {"success": bool, "message": str}
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name()

            # Still protect system-critical processes
            if pid in (0, 4) or name.lower() in (
                "system", "smss.exe", "csrss.exe", "wininit.exe",
                "services.exe", "lsass.exe", "svchost.exe",
            ):
                return {
                    "success": False,
                    "message": f"Cannot kill system process: {name} (PID {pid})",
                }

            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

            self._kill_log.append({
                "timestamp": datetime.now().isoformat(),
                "pid": pid,
                "process_name": name,
                "success": True,
                "manual": True,
            })

            log_threat(
                process_name=name,
                pid=pid,
                score=0,
                level="malicious",
                reasons=["Manually terminated by user"],
                action="manual_stop",
            )

            return {"success": True, "message": f"Terminated {name} (PID {pid})"}

        except psutil.NoSuchProcess:
            return {"success": False, "message": f"Process PID {pid} not found"}
        except psutil.AccessDenied:
            return {
                "success": False,
                "message": f"Access denied. Run Auraveil as Administrator.",
            }
        except Exception as e:
            return {"success": False, "message": str(e)}

    def get_kill_log(self) -> list[dict]:
        """Return the log of killed processes."""
        return list(self._kill_log)

    def clear_cooldowns(self):
        """Reset all alert cooldowns (useful during testing)."""
        self._alert_cooldowns.clear()
