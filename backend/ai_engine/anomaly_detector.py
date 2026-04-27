"""
Auraveil — Anomaly Detector (Phase 2)
Ensemble anomaly detection: Isolation Forest + LSTM autoencoder.
SHAP explainability integration, periodic retraining support.
"""

import os
import joblib
import logging
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from backend.config import (
    CONTAMINATION_RATE,
    MIN_TRAINING_SAMPLES,
    THRESHOLD_SAFE,
    THRESHOLD_SUSPICIOUS,
    MODEL_DIR,
    MODEL_PATH,
    ENSEMBLE_WEIGHT_IF,
    ENSEMBLE_WEIGHT_LSTM,
    LSTM_WINDOW_SIZE,
)
from backend.ai_engine.feature_engineering import FeatureEngineering
from backend.ai_engine.sequence_detector import SequenceDetector
from backend.ai_engine.explainer import ModelExplainer

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Ensemble anomaly detection for process behavior.

    Phase 1: Isolation Forest (single-snapshot scoring).
    Phase 2: + LSTM autoencoder (temporal patterns) + SHAP explainability.

    Final score = weighted combination of IF and LSTM scores.
    """

    def __init__(self, contamination: float = CONTAMINATION_RATE):
        # ─── Isolation Forest (Phase 1) ──────────────────────────────────
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self._baseline_means: np.ndarray | None = None
        self._baseline_stds: np.ndarray | None = None
        self._training_data: list[np.ndarray] = []

        # ─── LSTM Sequence Detector (Phase 2) ────────────────────────────
        self.sequence_detector = SequenceDetector()
        self._feature_history: list[np.ndarray] = []

        # ─── SHAP Explainer (Phase 2) ────────────────────────────────────
        self.explainer = ModelExplainer(
            feature_names=[
                n.replace("_", " ").replace("io ", "I/O ").title()
                for n in FeatureEngineering.FEATURE_NAMES
            ]
        )

        # ─── Ensemble weights ────────────────────────────────────────────
        self.weight_if = ENSEMBLE_WEIGHT_IF
        self.weight_lstm = ENSEMBLE_WEIGHT_LSTM

        # ─── Metadata ────────────────────────────────────────────────────
        self.last_trained_at: str | None = None

    def prepare_features(self, process_data: dict) -> np.ndarray:
        """Extract features from a single process snapshot."""
        return FeatureEngineering.extract_process_features(process_data)

    def accumulate_training_data(self, process_list: list[dict]):
        """
        Accumulate process snapshots for eventual training.
        Also builds feature history for LSTM sequence generation.
        """
        for proc in process_list:
            features = self.prepare_features(proc)
            self._training_data.append(features)

        # Cap training data to prevent unbounded memory growth
        MAX_TRAINING_BUFFER = 10_000
        if len(self._training_data) > MAX_TRAINING_BUFFER:
            self._training_data = self._training_data[-MAX_TRAINING_BUFFER:]

        # Aggregate system-level features for LSTM sequences
        if process_list:
            avg_features = np.mean(
                [self.prepare_features(p) for p in process_list], axis=0
            )
            self._feature_history.append(avg_features)

            # Cap feature history (1 hour at 1s intervals)
            MAX_FEATURE_HISTORY = 3_600
            if len(self._feature_history) > MAX_FEATURE_HISTORY:
                self._feature_history = self._feature_history[-MAX_FEATURE_HISTORY:]

            # Build LSTM sequences when enough history
            if len(self._feature_history) >= LSTM_WINDOW_SIZE:
                sequences = FeatureEngineering.build_sequences(
                    self._feature_history, LSTM_WINDOW_SIZE
                )
                if sequences:
                    self.sequence_detector.accumulate_sequence(sequences[-1])

    @property
    def training_samples_collected(self) -> int:
        return len(self._training_data)

    @property
    def ready_to_train(self) -> bool:
        return len(self._training_data) >= MIN_TRAINING_SAMPLES

    def train(self, historical_data: list[dict] | None = None):
        """
        Train the Isolation Forest (and optionally LSTM) on baseline data.
        """
        if historical_data:
            features = FeatureEngineering.batch_extract_features(historical_data)
        elif self._training_data:
            features = np.vstack(self._training_data)
        else:
            logger.warning("No training data available.")
            return

        if len(features) < 10:
            logger.warning(f"Only {len(features)} samples — too few to train.")
            return

        # ─── Isolation Forest ────────────────────────────────────────────
        self.scaler.fit(features)
        scaled = self.scaler.transform(features)

        self._baseline_means = np.mean(features, axis=0)
        self._baseline_stds = np.std(features, axis=0)
        self._baseline_stds[self._baseline_stds == 0] = 1.0

        self.model.fit(scaled)
        self.is_trained = True
        self.last_trained_at = datetime.now().isoformat()

        logger.info(
            f"Isolation Forest trained on {len(features)} samples. "
            f"Baseline means: {self._baseline_means.tolist()}"
        )

        # ─── SHAP Explainer ──────────────────────────────────────────────
        try:
            self.explainer.fit(self.model, self.scaler, features)
        except Exception as e:
            logger.warning(f"SHAP explainer fit failed (non-critical): {e}")

        # ─── LSTM Autoencoder ────────────────────────────────────────────
        if (
            self.sequence_detector.available
            and self.sequence_detector.training_sequences_collected >= 10
        ):
            try:
                self.sequence_detector.train()
                self.sequence_detector.save_model()
            except Exception as e:
                logger.warning(f"LSTM training failed (non-critical): {e}")

    def retrain(self):
        """
        Retrain the model on accumulated data, then clear training buffer.
        Used for periodic baseline updates.
        """
        logger.info("Retraining anomaly detector...")
        self.train()
        self._training_data = []
        self._feature_history = []
        self.save_model()

    def predict(self, process_data: dict) -> tuple[int, list[str]]:
        """
        Score a process using ensemble (IF + LSTM).

        Returns:
            (threat_score, reasons)
            - threat_score: 0–100, higher = more anomalous
            - reasons: Human-readable explanation strings
        """
        if not self.is_trained:
            return 0, []

        features = self.prepare_features(process_data).reshape(1, -1)
        scaled = self.scaler.transform(features)

        # ─── Isolation Forest Score ──────────────────────────────────────
        raw_score = self.model.decision_function(scaled)[0]
        if_score = float(np.clip((0.5 - raw_score) * 100, 0, 100))

        # ─── LSTM Score (if available) ───────────────────────────────────
        lstm_score = 0.0
        if self.sequence_detector.is_trained and len(self._feature_history) >= LSTM_WINDOW_SIZE:
            recent_window = np.stack(self._feature_history[-LSTM_WINDOW_SIZE:])
            lstm_score = self.sequence_detector.predict(recent_window)

        # ─── Ensemble ────────────────────────────────────────────────────
        if self.sequence_detector.is_trained:
            threat_score = int(
                self.weight_if * if_score + self.weight_lstm * lstm_score
            )
        else:
            threat_score = int(if_score)

        threat_score = max(0, min(100, threat_score))

        # ─── Reason Codes ────────────────────────────────────────────────
        reasons = self._generate_reasons(features[0], process_data)

        return threat_score, reasons

    def explain_process(self, process_data: dict) -> dict:
        """
        Generate detailed SHAP explanation for a specific process.
        Called by the /api/processes/{pid}/explain endpoint.
        """
        if not self.is_trained or not self.explainer.available:
            return {"shap_values": [], "top_features": [], "summary": "Model not ready"}

        features = self.prepare_features(process_data).reshape(1, -1)
        explanations = self.explainer.explain(features, self.scaler, top_k=5)
        return explanations[0] if explanations else {}

    def classify(self, threat_score: int) -> str:
        """Classify a threat score into a risk level."""
        if threat_score <= THRESHOLD_SAFE:
            return "safe"
        elif threat_score <= THRESHOLD_SUSPICIOUS:
            return "suspicious"
        else:
            return "malicious"

    def _generate_reasons(
        self, raw_features: np.ndarray, process_data: dict
    ) -> list[str]:
        """
        Generate human-readable reason codes by comparing feature values
        to baseline mean ± 3σ.
        """
        if self._baseline_means is None or self._baseline_stds is None:
            return []

        reasons = []
        feature_names = FeatureEngineering.FEATURE_NAMES

        for i, (value, mean, std, name) in enumerate(
            zip(raw_features, self._baseline_means, self._baseline_stds, feature_names)
        ):
            if std == 0:
                continue

            z_score = (value - mean) / std

            if z_score > 3.0:
                multiplier = round(value / mean, 1) if mean > 0 else 0
                readable_name = name.replace("_", " ").replace("io ", "I/O ")
                if multiplier > 1:
                    reasons.append(f"{readable_name} {multiplier}x above normal")
                else:
                    reasons.append(f"{readable_name} significantly elevated")

            elif z_score < -3.0:
                readable_name = name.replace("_", " ").replace("io ", "I/O ")
                reasons.append(f"{readable_name} unusually low")

        return reasons

    def get_model_info(self) -> dict:
        """Return model metadata for the /api/model/info endpoint."""
        return {
            "is_trained": self.is_trained,
            "last_trained_at": self.last_trained_at,
            "training_samples": self.training_samples_collected,
            "isolation_forest": {
                "n_estimators": self.model.n_estimators,
                "contamination": float(self.model.contamination),
            },
            "lstm": {
                "available": self.sequence_detector.available,
                "is_trained": self.sequence_detector.is_trained,
                "sequences_collected": self.sequence_detector.training_sequences_collected,
            },
            "shap": {
                "available": self.explainer.available,
            },
            "ensemble_weights": {
                "isolation_forest": self.weight_if,
                "lstm": self.weight_lstm,
            },
        }

    def save_model(self, path: str | None = None):
        """Persist trained model, scaler, and baselines to disk."""
        path = path or MODEL_PATH
        os.makedirs(os.path.dirname(path), exist_ok=True)

        state = {
            "model": self.model,
            "scaler": self.scaler,
            "is_trained": self.is_trained,
            "baseline_means": self._baseline_means,
            "baseline_stds": self._baseline_stds,
            "last_trained_at": self.last_trained_at,
        }

        joblib.dump(state, path)

        logger.info(f"Model saved to {path}")

    def load_model(self, path: str | None = None) -> bool:
        """Load a pre-trained model from disk. Returns True on success."""
        path = path or MODEL_PATH

        if not os.path.exists(path):
            logger.info(f"No saved model found at {path}")
            return False

        try:
            state = joblib.load(path)

            self.model = state["model"]
            self.scaler = state["scaler"]
            self.is_trained = state["is_trained"]
            self._baseline_means = state["baseline_means"]
            self._baseline_stds = state["baseline_stds"]
            self.last_trained_at = state.get("last_trained_at")

            # Also try to load LSTM
            self.sequence_detector.load_model()

            # Re-fit SHAP if we have baseline data
            if self.is_trained and self._baseline_means is not None:
                try:
                    # Build a small synthetic background set from baseline stats
                    bg = np.random.normal(
                        self._baseline_means,
                        self._baseline_stds,
                        size=(100, len(self._baseline_means)),
                    )
                    self.explainer.fit(self.model, self.scaler, bg)
                except Exception:
                    pass

            logger.info(f"Model loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
