from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import SecurityConfig


def _parse_ts(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class NodeModelState:
    count: int = 0
    mean: list[float] = field(default_factory=list)
    m2: list[float] = field(default_factory=list)
    last_ts: datetime | None = None
    recent_confidence: deque[float] = field(default_factory=lambda: deque(maxlen=25))


@dataclass
class AIAnomalyResult:
    is_anomaly: bool
    confidence: float
    score: float


class AIAnomalyDetector:
    """Unsupervised online detector using per-node multivariate z-score statistics."""

    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._state: dict[str, NodeModelState] = defaultdict(NodeModelState)

    def ensure_identity(self, identity: str) -> None:
        _ = self._state[identity]

    def observe(
        self,
        identity: str,
        role: str,
        receiver_id: str,
        payload_type: str,
        battery: float | None,
        temp_c: float | None,
        timestamp: str,
    ) -> AIAnomalyResult:
        state = self._state[identity]
        feature = self._build_feature(state, role, receiver_id, payload_type, battery, temp_c, timestamp)
        confidence, score = self._score(state, feature)
        self._update(state, feature)
        state.recent_confidence.append(confidence)
        return AIAnomalyResult(
            is_anomaly=confidence >= self.config.ai_anomaly_threshold,
            confidence=confidence,
            score=score,
        )

    def risk_score(self, identity: str) -> float:
        state = self._state.get(identity)
        if state is None or not state.recent_confidence:
            return 0.0
        return round(sum(state.recent_confidence) / len(state.recent_confidence), 3)

    @staticmethod
    def _build_feature(
        state: NodeModelState,
        role: str,
        receiver_id: str,
        payload_type: str,
        battery: float | None,
        temp_c: float | None,
        timestamp: str,
    ) -> list[float]:
        now = _parse_ts(timestamp)
        if state.last_ts is None:
            delta_sec = 1.0
        else:
            delta_sec = max(0.01, min(20.0, (now - state.last_ts).total_seconds()))
        state.last_ts = now

        battery_norm = 0.0 if battery is None else max(0.0, min(1.0, battery / 100.0))
        temp_norm = 0.5 if temp_c is None else max(0.0, min(1.0, (temp_c + 60.0) / 140.0))
        role_satellite = 1.0 if role == "satellite" else 0.0
        role_ground = 1.0 if role == "ground_station" else 0.0
        is_command = 1.0 if payload_type == "command" else 0.0
        receiver_is_ground = 1.0 if receiver_id.startswith("GROUND-") else 0.0
        delta_norm = delta_sec / 20.0

        return [
            role_satellite,
            role_ground,
            is_command,
            receiver_is_ground,
            battery_norm,
            temp_norm,
            delta_norm,
        ]

    def _score(self, state: NodeModelState, feature: list[float]) -> tuple[float, float]:
        if state.count < self.config.ai_warmup_samples or not state.mean:
            return 0.0, 0.0

        z_values: list[float] = []
        for i, x in enumerate(feature):
            variance = max(state.m2[i] / max(1, state.count - 1), 1e-4)
            std = math.sqrt(variance)
            z = abs((x - state.mean[i]) / std)
            z_values.append(min(8.0, z))

        # Mean absolute z-score, then converted to [0..1] confidence.
        score = sum(z_values) / len(z_values)
        confidence = 1.0 / (1.0 + math.exp(-1.35 * (score - 2.4)))
        return confidence, score

    @staticmethod
    def _update(state: NodeModelState, feature: list[float]) -> None:
        if not state.mean:
            state.mean = feature[:]
            state.m2 = [0.0 for _ in feature]
            state.count = 1
            return

        state.count += 1
        for i, x in enumerate(feature):
            delta = x - state.mean[i]
            state.mean[i] += delta / state.count
            delta2 = x - state.mean[i]
            state.m2[i] += delta * delta2
