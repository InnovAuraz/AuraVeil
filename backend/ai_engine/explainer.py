"""
Auraveil — SHAP Explainer
Generates per-feature importance explanations for anomaly detector predictions.
Falls back to z-score reasons if SHAP is unavailable.
"""

import logging
import numpy as np

logger = logging.getLogger(__name__)

# Try to import SHAP — optional dependency
try:
    import shap

    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False
    logger.warning("SHAP not available. Using z-score explainability only.")


class ModelExplainer:
    """
    SHAP-based model explainability for Isolation Forest predictions.

    Generates per-feature SHAP values for flagged processes and produces
    human-readable importance rankings.
    """

    def __init__(self, feature_names: list[str] | None = None):
        self.feature_names = feature_names or [
            "CPU %",
            "Memory %",
            "Threads",
            "I/O Read Bytes",
            "I/O Write Bytes",
            "I/O Read Count",
            "I/O Write Count",
        ]
        self._explainer = None
        self._is_fitted = False

    @property
    def available(self) -> bool:
        return SHAP_AVAILABLE and self._is_fitted

    def fit(self, model, scaler, background_data: np.ndarray):
        """
        Initialize the SHAP explainer with a background dataset.

        Args:
            model: Trained sklearn IsolationForest.
            scaler: Fitted StandardScaler.
            background_data: Sample of normal data for SHAP background
                             (100–500 samples recommended).
        """
        if not SHAP_AVAILABLE:
            return

        try:
            # Use a smaller background set for performance
            if len(background_data) > 200:
                indices = np.random.choice(
                    len(background_data), 200, replace=False
                )
                background_data = background_data[indices]

            # Scale background data
            scaled_bg = scaler.transform(background_data)

            # Create a wrapper that returns anomaly scores (not labels)
            def model_predict(X):
                return -model.decision_function(X)

            self._explainer = shap.KernelExplainer(
                model_predict, scaled_bg
            )
            self._is_fitted = True
            logger.info(
                f"SHAP explainer fitted with {len(scaled_bg)} background samples"
            )
        except Exception as e:
            logger.error(f"Failed to fit SHAP explainer: {e}")
            self._is_fitted = False

    def explain(
        self,
        features: np.ndarray,
        scaler,
        top_k: int = 3,
    ) -> list[dict]:
        """
        Generate SHAP explanations for one or more process feature vectors.

        Args:
            features: (n_samples, n_features) raw feature matrix.
            scaler: Fitted StandardScaler to transform features.
            top_k: Number of top contributing features to return.

        Returns:
            List of dicts, one per sample:
            [
                {
                    "shap_values": [float, ...],
                    "top_features": [
                        {"feature": "CPU %", "importance": 0.42, "direction": "high"},
                        ...
                    ],
                    "summary": "CPU % was the biggest factor (high)"
                },
                ...
            ]
        """
        if not self.available:
            return [{"shap_values": [], "top_features": [], "summary": ""}] * len(
                features
            )

        try:
            scaled = scaler.transform(features.reshape(-1, len(self.feature_names)))
            shap_values = self._explainer.shap_values(scaled, nsamples=100)

            results = []
            for i in range(len(scaled)):
                sv = shap_values[i] if shap_values.ndim > 1 else shap_values

                # Rank features by absolute SHAP value
                abs_sv = np.abs(sv)
                top_indices = np.argsort(abs_sv)[::-1][:top_k]

                top_features = []
                for idx in top_indices:
                    direction = "high" if sv[idx] > 0 else "low"
                    top_features.append(
                        {
                            "feature": self.feature_names[idx],
                            "importance": round(float(abs_sv[idx]), 4),
                            "direction": direction,
                        }
                    )

                # Build summary string
                if top_features:
                    best = top_features[0]
                    summary = (
                        f"{best['feature']} was the biggest factor ({best['direction']})"
                    )
                else:
                    summary = ""

                results.append(
                    {
                        "shap_values": sv.tolist() if hasattr(sv, "tolist") else [],
                        "top_features": top_features,
                        "summary": summary,
                    }
                )

            return results

        except Exception as e:
            logger.error(f"SHAP explanation failed: {e}")
            return [{"shap_values": [], "top_features": [], "summary": ""}] * len(
                features
            )
