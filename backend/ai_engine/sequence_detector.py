"""
Auraveil — LSTM Autoencoder Sequence Detector
Learns temporal patterns in process behavior over sliding windows.
Detects anomalies via reconstruction error (high error = anomalous).
Falls back gracefully if PyTorch is unavailable.
"""

import os
import logging
import numpy as np

from backend.config import (
    LSTM_WINDOW_SIZE,
    LSTM_HIDDEN_DIM,
    MODEL_DIR,
)

logger = logging.getLogger(__name__)

# Try to import PyTorch — optional dependency
try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available. LSTM sequence detection disabled.")


# ─── Model Definition ────────────────────────────────────────────────────────

if TORCH_AVAILABLE:

    class LSTMAutoencoder(nn.Module):
        """
        LSTM autoencoder for sequence anomaly detection.

        Encoder compresses a sequence of feature vectors into a latent
        representation. Decoder reconstructs the input. High reconstruction
        error indicates anomalous temporal patterns.
        """

        def __init__(self, input_dim: int, hidden_dim: int, num_layers: int = 1):
            super().__init__()
            self.input_dim = input_dim
            self.hidden_dim = hidden_dim
            self.num_layers = num_layers

            # Encoder
            self.encoder = nn.LSTM(
                input_size=input_dim,
                hidden_size=hidden_dim,
                num_layers=num_layers,
                batch_first=True,
            )

            # Decoder
            self.decoder = nn.LSTM(
                input_size=hidden_dim,
                hidden_size=hidden_dim,
                num_layers=num_layers,
                batch_first=True,
            )

            # Output projection back to input dimension
            self.output_layer = nn.Linear(hidden_dim, input_dim)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """
            Args:
                x: (batch, seq_len, input_dim)
            Returns:
                reconstructed: (batch, seq_len, input_dim)
            """
            # Encode
            _, (hidden, cell) = self.encoder(x)

            # Repeat the latent vector for each timestep
            seq_len = x.size(1)
            decoder_input = hidden[-1].unsqueeze(1).repeat(1, seq_len, 1)

            # Decode
            decoder_output, _ = self.decoder(decoder_input)

            # Project to input space
            reconstructed = self.output_layer(decoder_output)
            return reconstructed


# ─── Sequence Detector ────────────────────────────────────────────────────────

class SequenceDetector:
    """
    Wraps the LSTM autoencoder for training and inference.

    - Accumulates sliding-window sequences of process features
    - Trains the autoencoder on normal behavior
    - Scores new sequences by reconstruction error
    """

    LSTM_MODEL_PATH = os.path.join(MODEL_DIR, "lstm_autoencoder.pt")

    def __init__(
        self,
        input_dim: int = 7,
        hidden_dim: int = LSTM_HIDDEN_DIM,
        window_size: int = LSTM_WINDOW_SIZE,
    ):
        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.window_size = window_size
        self.is_trained = False
        self._training_sequences: list[np.ndarray] = []
        self._error_threshold: float = 0.0

        if TORCH_AVAILABLE:
            self.model = LSTMAutoencoder(input_dim, hidden_dim)
            self.criterion = nn.MSELoss(reduction="none")
        else:
            self.model = None
            self.criterion = None

    @property
    def available(self) -> bool:
        return TORCH_AVAILABLE

    def accumulate_sequence(self, window: np.ndarray):
        """
        Store a sliding-window sequence for training.

        Args:
            window: numpy array of shape (window_size, input_dim)
        """
        if not TORCH_AVAILABLE:
            return
        if window.shape[0] == self.window_size:
            self._training_sequences.append(window.astype(np.float32))

    @property
    def training_sequences_collected(self) -> int:
        return len(self._training_sequences)

    def train(self, epochs: int = 50, lr: float = 1e-3, batch_size: int = 32):
        """
        Train the LSTM autoencoder on accumulated normal sequences.
        """
        if not TORCH_AVAILABLE or len(self._training_sequences) < 10:
            logger.warning(
                f"Cannot train LSTM: "
                f"{'PyTorch unavailable' if not TORCH_AVAILABLE else f'only {len(self._training_sequences)} sequences'}"
            )
            return

        logger.info(f"Training LSTM autoencoder on {len(self._training_sequences)} sequences...")

        # Prepare data
        data = np.stack(self._training_sequences)
        tensor_data = torch.FloatTensor(data)
        dataset = TensorDataset(tensor_data)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        # Train
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
        self.model.train()

        for epoch in range(epochs):
            total_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                reconstructed = self.model(batch)
                loss = self.criterion(reconstructed, batch).mean()
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

            if (epoch + 1) % 10 == 0:
                avg_loss = total_loss / len(loader)
                logger.info(f"  LSTM epoch {epoch + 1}/{epochs}, loss: {avg_loss:.6f}")

        # Compute error threshold (mean + 3*std of training reconstruction errors)
        self.model.eval()
        with torch.no_grad():
            all_errors = []
            for (batch,) in loader:
                reconstructed = self.model(batch)
                errors = self.criterion(reconstructed, batch).mean(dim=(1, 2))
                all_errors.append(errors)

            all_errors = torch.cat(all_errors)
            mean_error = all_errors.mean().item()
            std_error = all_errors.std().item()
            self._error_threshold = mean_error + 3 * std_error

        self.is_trained = True
        logger.info(
            f"LSTM autoencoder trained. "
            f"Error threshold: {self._error_threshold:.6f}"
        )

    def predict(self, window: np.ndarray) -> float:
        """
        Score a sequence for anomaly (0–100).

        Args:
            window: numpy array of shape (window_size, input_dim)

        Returns:
            Anomaly score 0–100 (higher = more anomalous)
        """
        if not TORCH_AVAILABLE or not self.is_trained:
            return 0.0

        self.model.eval()
        with torch.no_grad():
            tensor = torch.FloatTensor(window.astype(np.float32)).unsqueeze(0)
            reconstructed = self.model(tensor)
            error = self.criterion(reconstructed, tensor).mean().item()

        # Normalize: 0 at no error, 100 at 2× threshold
        if self._error_threshold > 0:
            normalized = min((error / self._error_threshold) * 50, 100)
        else:
            normalized = 0.0

        return float(normalized)

    def save_model(self, path: str | None = None):
        """Save LSTM model and threshold to disk."""
        if not TORCH_AVAILABLE or not self.is_trained:
            return

        path = path or self.LSTM_MODEL_PATH
        os.makedirs(os.path.dirname(path), exist_ok=True)

        torch.save(
            {
                "model_state": self.model.state_dict(),
                "error_threshold": self._error_threshold,
                "input_dim": self.input_dim,
                "hidden_dim": self.hidden_dim,
                "window_size": self.window_size,
            },
            path,
        )
        logger.info(f"LSTM model saved to {path}")

    def load_model(self, path: str | None = None) -> bool:
        """Load LSTM model from disk. Returns True on success."""
        if not TORCH_AVAILABLE:
            return False

        path = path or self.LSTM_MODEL_PATH
        if not os.path.exists(path):
            logger.info(f"No saved LSTM model at {path}")
            return False

        try:
            checkpoint = torch.load(path, map_location="cpu", weights_only=True)
            self.model.load_state_dict(checkpoint["model_state"])
            self._error_threshold = checkpoint["error_threshold"]
            self.is_trained = True
            logger.info(f"LSTM model loaded from {path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load LSTM model: {e}")
            return False
