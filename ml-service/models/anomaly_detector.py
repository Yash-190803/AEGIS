import os
import threading

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    def __init__(self, contamination=0.1, n_estimators=100):
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
        )
        self.is_trained = False
        self._lock = threading.Lock()
        self.training_vectors = []

    def train_on_baseline(self):
        """Generate synthetic baseline data, train the model, and retain examples for feedback retraining."""
        rng = np.random.default_rng(42)
        normal = []
        for _ in range(1000):
            normal.append([
                rng.integers(1, 20),
                rng.integers(0, 3),
                rng.integers(0, 3),
                rng.uniform(0, 0.12),
                rng.integers(1, 3),
                0,
                0,
                rng.uniform(1, 30),
                rng.uniform(0, 0.08),
            ])
        anomalous = []
        for _ in range(100):
            anomalous.append([
                rng.integers(30, 220),
                rng.integers(20, 160),
                rng.integers(0, 8),
                rng.uniform(0.4, 0.95),
                rng.integers(3, 40),
                rng.integers(0, 8),
                rng.integers(0, 8),
                rng.uniform(80, 400),
                rng.uniform(0.15, 0.9),
            ])
        self.training_vectors = normal + anomalous
        self.model.fit(np.array(self.training_vectors, dtype=float))
        self.is_trained = True
        return {"normal_examples": len(normal), "anomalous_examples": len(anomalous)}

    def score_batch(self, feature_vectors: list) -> list:
        """Convert Isolation Forest scores (-1 to 0) to anomaly scores (0 to 1)."""
        if not self.is_trained:
            self.train_on_baseline()
        if not isinstance(feature_vectors, list) or len(feature_vectors) == 0:
            raise ValueError("feature_vectors must be a non-empty list")
        matrix = np.array(feature_vectors, dtype=float)
        if matrix.ndim == 1:
            matrix = matrix.reshape(1, -1)
        raw_scores = self.model.score_samples(matrix)
        return [max(0.0, min(1.0, float(score * -2))) for score in raw_scores]

    def get_recommendation(self, anomaly_score: float, ml_confidence: float) -> str:
        if anomaly_score > 0.7 and ml_confidence > 0.8:
            return "ESCALATE_TO_LLM"
        if anomaly_score > 0.4:
            return "MONITOR"
        return "DISCARD"

    def update_with_feedback(self, new_examples: list):
        """Thread-safe retraining with additional labeled or raw feature examples."""
        if not isinstance(new_examples, list) or len(new_examples) == 0:
            raise ValueError("new_examples must be a non-empty list")
        vectors = [self._extract_vector(example) for example in new_examples]
        with self._lock:
            if not self.training_vectors:
                self.train_on_baseline()
            self.training_vectors.extend(vectors)
            self.model.fit(np.array(self.training_vectors, dtype=float))
            self.is_trained = True
        return {"trained_examples": len(self.training_vectors), "new_examples": len(vectors)}

    def save(self, path):
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "is_trained": self.is_trained,
                "training_vectors": self.training_vectors,
            },
            path,
        )
        return path

    def load(self, path) -> bool:
        if not os.path.exists(path):
            return False
        payload = joblib.load(path)
        self.model = payload["model"]
        self.is_trained = bool(payload.get("is_trained", True))
        self.training_vectors = payload.get("training_vectors", [])
        return True

    def _extract_vector(self, example):
        if isinstance(example, dict) and "features" in example:
            return [float(value) for value in example["features"]]
        if isinstance(example, dict) and "vector" in example:
            return [float(value) for value in example["vector"]]
        if isinstance(example, (list, tuple)):
            return [float(value) for value in example]
        raise ValueError("feedback examples must be vectors or dicts with features/vector")