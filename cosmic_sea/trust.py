from __future__ import annotations

import random
from dataclasses import dataclass, field

from .config import SecurityConfig
from .models import Event


@dataclass
class TrustState:
    score: float = 100.0
    stage: str = "healthy"
    role: str = "satellite"
    isolated: bool = False
    alerts: list[Event] = field(default_factory=list)


class TrustEngine:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._state: dict[str, TrustState] = {}

    def ensure_identity(self, identity: str, role: str = "satellite") -> None:
        self._state.setdefault(identity, TrustState(role=role))

    def has_identity(self, identity: str) -> bool:
        return identity in self._state

    def role(self, identity: str) -> str:
        return self._state[identity].role

    def can_transmit(self, identity: str, payload_type: str) -> bool:
        state = self._state[identity]
        if state.stage == "isolated":
            return False
        if state.stage == "quarantine":
            return payload_type == "telemetry"
        if state.stage == "throttle":
            return random.random() >= self.config.throttle_drop_ratio
        return True

    def mark_good(self, identity: str) -> None:
        state = self._state[identity]
        if state.isolated:
            return
        state.score = min(100.0, state.score + self.config.trust_bonus_valid)
        self._update_stage(identity)

    def apply_violation(self, identity: str, reason: str, severity: str, confidence: float) -> None:
        state = self._state[identity]
        if state.isolated:
            return

        role_weight = 1.15 if state.role == "ground_station" else 1.0
        severity_weight = 1.0 if severity == "minor" else 2.0
        confidence_weight = 0.6 + max(0.0, min(1.0, confidence))
        base = self.config.trust_decay_minor if severity == "minor" else self.config.trust_decay_major
        delta = base * role_weight * severity_weight * confidence_weight

        state.score = max(0.0, state.score - delta)
        state.alerts.append(
            Event(
                level="warning" if severity == "minor" else "critical",
                message=f"{identity}: {reason} (confidence={confidence:.2f})",
            )
        )
        self._update_stage(identity)

    def _update_stage(self, identity: str) -> None:
        state = self._state[identity]
        old_stage = state.stage

        if state.score <= self.config.trust_isolate_threshold:
            state.stage = "isolated"
            state.isolated = True
        elif state.score <= self.config.trust_quarantine_threshold:
            state.stage = "quarantine"
        elif state.score <= self.config.trust_throttle_threshold:
            state.stage = "throttle"
        elif state.score <= self.config.trust_monitor_threshold:
            state.stage = "monitor"
        else:
            state.stage = "healthy"

        if state.stage != old_stage:
            level = "critical" if state.stage in {"quarantine", "isolated"} else "warning"
            state.alerts.append(
                Event(level=level, message=f"{identity} stage transition: {old_stage} -> {state.stage}")
            )

    def get_state(self, identity: str) -> TrustState:
        return self._state[identity]

    def snapshot(self) -> dict[str, dict[str, object]]:
        data: dict[str, dict[str, object]] = {}
        for ident, state in self._state.items():
            data[ident] = {
                "score": round(state.score, 2),
                "stage": state.stage,
                "isolated": state.isolated,
                "role": state.role,
                "alerts": [a.__dict__ for a in state.alerts[-12:]],
            }
        return data

    def all_alerts(self, limit: int = 20) -> list[dict[str, str]]:
        collected: list[dict[str, str]] = []
        for state in self._state.values():
            for alert in state.alerts:
                collected.append(alert.__dict__)
        return sorted(collected, key=lambda x: x["timestamp"], reverse=True)[:limit]
