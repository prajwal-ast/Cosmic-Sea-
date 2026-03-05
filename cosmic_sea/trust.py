from __future__ import annotations

from dataclasses import dataclass, field

from .config import SecurityConfig
from .models import Event


@dataclass
class TrustState:
    score: float = 100.0
    isolated: bool = False
    alerts: list[Event] = field(default_factory=list)


class TrustEngine:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._state: dict[str, TrustState] = {}

    def ensure_identity(self, identity: str) -> None:
        self._state.setdefault(identity, TrustState())

    def has_identity(self, identity: str) -> bool:
        return identity in self._state

    def mark_good(self, identity: str) -> None:
        state = self._state[identity]
        if state.isolated:
            return
        state.score = min(100.0, state.score + self.config.trust_bonus_valid)

    def mark_minor_violation(self, identity: str, reason: str) -> None:
        self._penalize(identity, self.config.trust_decay_minor, reason)

    def mark_major_violation(self, identity: str, reason: str) -> None:
        self._penalize(identity, self.config.trust_decay_major, reason)

    def _penalize(self, identity: str, delta: float, reason: str) -> None:
        state = self._state[identity]
        if state.isolated:
            return
        state.score = max(0.0, state.score - delta)
        state.alerts.append(Event(level="warning", message=f"{identity}: {reason}"))
        if state.score <= self.config.isolate_threshold:
            state.isolated = True
            state.alerts.append(Event(level="critical", message=f"{identity} isolated (trust={state.score:.1f})"))

    def get_state(self, identity: str) -> TrustState:
        return self._state[identity]

    def snapshot(self) -> dict[str, dict[str, object]]:
        data: dict[str, dict[str, object]] = {}
        for ident, state in self._state.items():
            data[ident] = {
                "score": round(state.score, 2),
                "isolated": state.isolated,
                "alerts": [a.__dict__ for a in state.alerts[-10:]],
            }
        return data

    def all_alerts(self, limit: int = 20) -> list[dict[str, str]]:
        collected: list[dict[str, str]] = []
        for state in self._state.values():
            for alert in state.alerts:
                collected.append(alert.__dict__)
        return sorted(collected, key=lambda x: x["timestamp"], reverse=True)[:limit]
