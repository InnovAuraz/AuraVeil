"""
Auraveil — Global Configuration
All tunable parameters for the MVP.
"""

import os

# ─── Monitoring ───────────────────────────────────────────────────────────────

MONITOR_INTERVAL_SECONDS = 1        # Polling frequency
BUFFER_SIZE = 1800                  # 30 minutes of data at 1s intervals

# ─── AI Engine ────────────────────────────────────────────────────────────────

CONTAMINATION_RATE = 0.01           # Expected % of anomalous behavior
MIN_TRAINING_SAMPLES = 3600         # 1 hour of data before model trains
RETRAIN_INTERVAL_HOURS = 24         # How often to retrain baseline model

# ─── Phase 2: LSTM Sequence Detection ────────────────────────────────────────

LSTM_WINDOW_SIZE = 30               # Timesteps per sequence (30s at 1s interval)
LSTM_HIDDEN_DIM = 64                # LSTM hidden layer size

# ─── Phase 2: Ensemble Scoring ───────────────────────────────────────────────

ENSEMBLE_WEIGHT_IF = 0.6            # Isolation Forest weight
ENSEMBLE_WEIGHT_LSTM = 0.4          # LSTM autoencoder weight

# ─── Phase 2: Alert & Response ───────────────────────────────────────────────

ALERT_COOLDOWN_SECONDS = 60         # Don't re-alert same process within cooldown
PROCESS_SPAWN_BURST_THRESHOLD = 10  # Flag if a parent spawns this many children/min

# ─── Threat Thresholds ────────────────────────────────────────────────────────

THRESHOLD_SAFE = 30                 # Score 0–30
THRESHOLD_SUSPICIOUS = 70           # Score 31–70
# Score 71–100 = Malicious

# ─── Response ─────────────────────────────────────────────────────────────────

AUTO_STOP_ENABLED = False           # Disabled by default (safety-first)
AUTO_STOP_THRESHOLD = 90            # Only auto-stop above this score

# ─── Database ─────────────────────────────────────────────────────────────────

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "auraveil.db")
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "baseline_model.pkl")

# ─── API ──────────────────────────────────────────────────────────────────────

API_HOST = "127.0.0.1"
API_PORT = 8000
CORS_ORIGINS = ["http://localhost:5173"]  # Vite dev server

# ─── File Monitoring ─────────────────────────────────────────────────────────

WATCHED_PATHS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]

# ─── Network Monitoring (Scapy + Npcap) ──────────────────────────────────────

NETWORK_INTERFACE = None             # None = auto-detect default interface
PACKET_BUFFER_SIZE = 1000            # Max packets in memory
BPF_FILTER = "tcp or udp"           # Scapy BPF filter to reduce overhead
SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 31337]  # Known C2/backdoor ports
NPCAP_FALLBACK = True                # Fall back to psutil if Npcap unavailable
