"""
Auraveil — FastAPI Backend (Phase 2)
REST endpoints + WebSocket for real-time metrics streaming.
Phase 2: Process tracking, response engine, ensemble scoring, SHAP, retrain.
"""

import asyncio
import logging
import sys
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

# Ensure backend package is importable when running from backend/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import backend.config as config
from backend.config import (
    CORS_ORIGINS,
    MONITOR_INTERVAL_SECONDS,
    THRESHOLD_SAFE,
    THRESHOLD_SUSPICIOUS,
    RETRAIN_INTERVAL_HOURS,
)
from backend.monitoring.system_monitor import SystemMonitor
from backend.monitoring.file_monitor import FileActivityMonitor
from backend.monitoring.network_monitor import NetworkMonitor
from backend.monitoring.process_tracker import ProcessTracker
from backend.ai_engine.anomaly_detector import AnomalyDetector
from backend.response_engine import ResponseEngine
from backend.database.models import (
    init_db,
    log_threat,
    get_threat_history,
    get_active_threats,
    resolve_threat,
    get_whitelist,
    add_to_whitelist,
    remove_from_whitelist,
    is_whitelisted,
)

logger = logging.getLogger(__name__)

# ─── Global State ─────────────────────────────────────────────────────────────

monitor = SystemMonitor()
file_monitor = FileActivityMonitor()
network_monitor = NetworkMonitor()
process_tracker = ProcessTracker()
detector = AnomalyDetector()
response_engine = ResponseEngine()

active_ws_connections: list[WebSocket] = []
start_time: datetime = datetime.now()
cached_alert_count: int = 0  # In-memory cache to avoid per-second DB queries (H3)


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    global start_time

    # Startup
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    logger.info("Auraveil backend starting...")

    init_db()
    detector.load_model()
    file_monitor.start()
    network_monitor.start_capture()
    start_time = datetime.now()

    # Launch background tasks
    monitor_task = asyncio.create_task(continuous_monitoring())
    retrain_task = asyncio.create_task(periodic_retrain())

    logger.info("Auraveil backend ready.")
    yield

    # Shutdown
    monitor_task.cancel()
    retrain_task.cancel()
    file_monitor.stop()
    network_monitor.stop_capture()
    logger.info("Auraveil backend stopped.")


# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Auraveil API",
    description="AI-powered behavioral threat detection",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Background Monitoring ────────────────────────────────────────────────────

async def continuous_monitoring():
    """Background loop: collect metrics, run detection, broadcast to WebSocket."""
    global cached_alert_count
    while True:
        try:
            # Collect all metrics
            metrics = monitor.collect_metrics()
            file_activity = file_monitor.get_activity_summary()
            network_summary = network_monitor.get_network_summary()

            # Process lifecycle tracking (Phase 2)
            lifecycle_events = process_tracker.scan()

            # Accumulate training data if model isn't trained yet
            if not detector.is_trained:
                detector.accumulate_training_data(metrics["processes"])

                # Auto-train when enough data is collected
                if detector.ready_to_train:
                    logger.info("Training anomaly detector on baseline data...")
                    detector.train()
                    detector.save_model()
                    logger.info("Anomaly detector trained and saved.")
            else:
                # Continue accumulating for LSTM sequences even after IF is trained
                detector.accumulate_training_data(metrics["processes"])

            # Score each process and evaluate threats
            enriched_processes = []
            new_alerts = []

            for proc in metrics["processes"]:
                threat_score, reasons = detector.predict(proc)
                risk_level = detector.classify(threat_score)

                proc_enriched = {
                    **proc,
                    "threat_score": threat_score,
                    "risk_level": risk_level,
                    "reasons": reasons,
                    "parent_pid": proc.get("ppid", 0),
                }
                enriched_processes.append(proc_enriched)

                # Evaluate via response engine (Phase 2: dedup + auto-stop)
                if threat_score > THRESHOLD_SAFE:
                    result = response_engine.evaluate(
                        process_name=proc.get("name", "unknown"),
                        pid=proc.get("pid", 0),
                        threat_score=threat_score,
                        risk_level=risk_level,
                        reasons=reasons,
                    )
                    if result["alert"]:
                        new_alerts.append(result["alert"])
                        cached_alert_count += 1

            # Build WebSocket payload
            ws_payload = {
                "timestamp": metrics["timestamp"],
                "system": metrics["system"],
                "network": network_summary,
                "file_activity": file_activity,
                "processes": enriched_processes,
                "active_alerts": cached_alert_count,
                "lifecycle": {
                    "new_processes": len(lifecycle_events["new_processes"]),
                    "terminated": len(lifecycle_events["terminated_processes"]),
                    "suspicious_spawns": lifecycle_events["suspicious_spawns"],
                },
                "new_alerts": new_alerts,
            }

            # Broadcast to all connected WebSocket clients
            disconnected = []
            for ws in active_ws_connections:
                try:
                    await ws.send_json(ws_payload)
                except Exception:
                    disconnected.append(ws)

            for ws in disconnected:
                active_ws_connections.remove(ws)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Monitoring loop error: {e}", exc_info=True)

        await asyncio.sleep(MONITOR_INTERVAL_SECONDS)


async def periodic_retrain():
    """Background task: periodically retrain the model on new baseline data."""
    while True:
        try:
            await asyncio.sleep(RETRAIN_INTERVAL_HOURS * 3600)

            if detector.is_trained and detector.training_samples_collected > 0:
                logger.info("Periodic retrain triggered...")
                detector.retrain()
                logger.info("Periodic retrain complete.")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Retrain error: {e}", exc_info=True)


# ─── REST Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/status")
async def get_status():
    """Engine status: trained state, uptime, buffer size, network mode."""
    uptime = (datetime.now() - start_time).total_seconds()
    model_info = detector.get_model_info()
    return {
        "status": "running",
        "uptime_seconds": int(uptime),
        "model_trained": detector.is_trained,
        "training_samples": detector.training_samples_collected,
        "buffer_size": monitor.get_buffer_size(),
        "file_monitor_active": file_monitor.is_running,
        "network_monitor_mode": network_monitor.mode,
        "ws_connections": len(active_ws_connections),
        "model": model_info,
    }


@app.get("/api/metrics/current")
async def get_current_metrics():
    """Get current system + process metrics (single snapshot)."""
    metrics = monitor.collect_metrics()
    network = network_monitor.get_network_summary()
    file_activity = file_monitor.get_activity_summary()

    # Enrich processes with threat scores
    for proc in metrics["processes"]:
        score, reasons = detector.predict(proc)
        proc["threat_score"] = score
        proc["risk_level"] = detector.classify(score)
        proc["reasons"] = reasons

    return {
        **metrics,
        "network": network,
        "file_activity": file_activity,
    }


@app.get("/api/threats/history")
async def get_threats_history(
    days: int = Query(default=7, ge=1, le=90),
    risk_level: str | None = Query(default=None),
):
    """Get threat history with optional filters."""
    if risk_level and risk_level not in ("safe", "suspicious", "malicious"):
        raise HTTPException(400, "risk_level must be safe, suspicious, or malicious")
    return get_threat_history(days=days, risk_level=risk_level)


@app.get("/api/threats/active")
async def get_threats_active():
    """Get unresolved threats."""
    return get_active_threats()


@app.post("/api/threats/{threat_id}/resolve")
async def resolve_threat_endpoint(threat_id: int):
    """Mark a threat as resolved."""
    global cached_alert_count
    if resolve_threat(threat_id):
        cached_alert_count = max(0, cached_alert_count - 1)
        return {"status": "resolved", "id": threat_id}
    raise HTTPException(404, f"Threat {threat_id} not found")


@app.get("/api/whitelist")
async def get_whitelist_endpoint():
    """List all whitelisted processes."""
    return get_whitelist()


@app.post("/api/whitelist/{process_name}")
async def add_whitelist_endpoint(process_name: str, reason: str = "User approved"):
    """Add a process to the whitelist."""
    if add_to_whitelist(process_name, reason):
        return {"status": "added", "process": process_name}
    raise HTTPException(409, f"{process_name} is already whitelisted")


@app.delete("/api/whitelist/{process_name}")
async def remove_whitelist_endpoint(process_name: str):
    """Remove a process from the whitelist."""
    if remove_from_whitelist(process_name):
        return {"status": "removed", "process": process_name}
    raise HTTPException(404, f"{process_name} not found in whitelist")


# ─── Phase 2: New Endpoints ──────────────────────────────────────────────────

@app.post("/api/processes/{pid}/kill")
async def kill_process_endpoint(pid: int):
    """Manually terminate a process by PID."""
    result = response_engine.manual_kill(pid)
    if result["success"]:
        return result
    raise HTTPException(400, result["message"])


@app.post("/api/model/retrain")
async def retrain_model_endpoint():
    """Force immediate model retrain."""
    if detector.training_samples_collected < 10:
        raise HTTPException(
            400,
            f"Not enough data to retrain ({detector.training_samples_collected} samples)",
        )
    detector.retrain()
    return {
        "status": "retrained",
        "samples": detector.training_samples_collected,
        "model_info": detector.get_model_info(),
    }


@app.get("/api/model/info")
async def get_model_info_endpoint():
    """Get model metadata: samples, last trained, ensemble weights, etc."""
    return detector.get_model_info()


@app.get("/api/processes/{pid}/explain")
async def explain_process_endpoint(pid: int):
    """Get SHAP explanation for a specific process."""
    # Find the process in the current snapshot
    metrics = monitor.collect_metrics()
    target = None
    for proc in metrics["processes"]:
        if proc.get("pid") == pid:
            target = proc
            break

    if target is None:
        raise HTTPException(404, f"Process PID {pid} not found")

    explanation = detector.explain_process(target)
    return {
        "pid": pid,
        "process_name": target.get("name", "unknown"),
        "explanation": explanation,
    }


@app.get("/api/settings")
async def get_settings():
    """Get current runtime configuration."""
    return {
        "monitor_interval": config.MONITOR_INTERVAL_SECONDS,
        "threshold_safe": config.THRESHOLD_SAFE,
        "threshold_suspicious": config.THRESHOLD_SUSPICIOUS,
        "auto_stop_enabled": config.AUTO_STOP_ENABLED,
        "auto_stop_threshold": config.AUTO_STOP_THRESHOLD,
        "alert_cooldown": config.ALERT_COOLDOWN_SECONDS,
        "ensemble_weight_if": config.ENSEMBLE_WEIGHT_IF,
        "ensemble_weight_lstm": config.ENSEMBLE_WEIGHT_LSTM,
    }


@app.post("/api/settings")
async def update_settings(settings: dict):
    """Update runtime configuration. Only known keys are accepted."""
    allowed = {
        "threshold_safe", "threshold_suspicious",
        "auto_stop_enabled", "auto_stop_threshold",
        "alert_cooldown",
    }
    updated = {}
    for key, value in settings.items():
        if key not in allowed:
            continue
        attr = key.upper()
        if hasattr(config, attr):
            setattr(config, attr, value)
            updated[key] = value
    if not updated:
        raise HTTPException(400, "No valid settings provided")
    return {"status": "updated", "settings": updated}


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """WebSocket endpoint for real-time metrics streaming."""
    await websocket.accept()
    active_ws_connections.append(websocket)
    logger.info(f"WebSocket client connected. Total: {len(active_ws_connections)}")

    try:
        # Keep connection alive — wait for client messages (e.g., pings)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in active_ws_connections:
            active_ws_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total: {len(active_ws_connections)}")
