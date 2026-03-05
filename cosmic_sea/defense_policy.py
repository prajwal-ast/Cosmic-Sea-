from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .config import SecurityConfig
from .models import Event
from .security import KeyRegistry
from .trust import TrustEngine


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class IncidentRecord:
    identity: str
    opened_at: datetime
    first_action_at: datetime | None = None
    contained_at: datetime | None = None
    resolved_at: datetime | None = None
    last_reason: str = ""
    violation_count: int = 0
    open: bool = True


class AutonomousDefenseSystem:
    """Closed-loop autonomous defense controller for detect-decide-respond metrics."""

    def __init__(
        self,
        config: SecurityConfig,
        trust: TrustEngine,
        keys: KeyRegistry,
        blocked: set[str],
    ) -> None:
        self.config = config
        self.trust = trust
        self.keys = keys
        self.blocked = blocked

        self._active_incidents: dict[str, IncidentRecord] = {}
        self._closed_incidents: list[IncidentRecord] = []
        self._good_streak: dict[str, int] = {}
        self._actions: list[dict[str, str]] = []
        self._action_counter: dict[str, int] = {
            "monitor": 0,
            "throttle": 0,
            "quarantine": 0,
            "isolate": 0,
        }

    def ensure_identity(self, identity: str) -> None:
        self._good_streak.setdefault(identity, 0)

    def on_good(self, identity: str) -> list[Event]:
        self._good_streak[identity] = self._good_streak.get(identity, 0) + 1
        incident = self._active_incidents.get(identity)
        if incident is None:
            return []

        state = self.trust.get_state(identity)
        # Autonomous recovery: resolve incident after sustained valid behavior.
        if state.stage in {"healthy", "monitor"} and self._good_streak[identity] >= 6:
            incident.open = False
            incident.resolved_at = _utc_now()
            self._closed_incidents.append(incident)
            del self._active_incidents[identity]
            return [Event(level="warning", message=f"Autonomous recovery: incident closed for {identity}")]
        return []

    def on_violation(self, identity: str, reason: str, severity: str, confidence: float) -> list[Event]:
        now = _utc_now()
        self._good_streak[identity] = 0

        incident = self._active_incidents.get(identity)
        if incident is None:
            incident = IncidentRecord(identity=identity, opened_at=now)
            self._active_incidents[identity] = incident
        incident.last_reason = reason
        incident.violation_count += 1

        before_stage = self.trust.get_state(identity).stage
        self.trust.apply_violation(identity, reason, severity=severity, confidence=confidence)
        after_state = self.trust.get_state(identity)

        events: list[Event] = []
        if incident.first_action_at is None:
            incident.first_action_at = now

        if after_state.stage in {"quarantine", "isolated"} and incident.contained_at is None:
            incident.contained_at = now

        if after_state.stage != before_stage:
            events.extend(self._emit_action(identity, after_state.stage))

        if after_state.stage == "isolated":
            self.blocked.add(identity)
            self.keys.revoke_identity(identity)
            events.append(Event(level="critical", message=f"Autonomous containment: {identity} revoked and isolated"))

        return events

    def kpis(self) -> dict[str, Any]:
        incidents = self._closed_incidents + list(self._active_incidents.values())
        total = len(incidents)
        contained = sum(1 for x in incidents if x.contained_at is not None)

        mttd = self._avg_seconds(
            [
                (x.first_action_at - x.opened_at).total_seconds()
                for x in incidents
                if x.first_action_at is not None
            ]
        )
        mttc = self._avg_seconds(
            [
                (x.contained_at - x.opened_at).total_seconds()
                for x in incidents
                if x.contained_at is not None
            ]
        )
        mttr = self._avg_seconds(
            [
                (x.resolved_at - x.opened_at).total_seconds()
                for x in self._closed_incidents
                if x.resolved_at is not None
            ]
        )

        return {
            "total_incidents": total,
            "active_incidents": len(self._active_incidents),
            "contained_incidents": contained,
            "containment_rate": round((contained / total), 3) if total else 0.0,
            "mttd_seconds": mttd,
            "mttc_seconds": mttc,
            "mttr_seconds": mttr,
            "action_counter": dict(self._action_counter),
            "recent_actions": self._actions[-15:],
        }

    def _emit_action(self, identity: str, stage: str) -> list[Event]:
        if stage not in self._action_counter:
            return []

        self._action_counter[stage] += 1
        action_msg = {
            "monitor": "raise_observation_level",
            "throttle": "adaptive_rate_limit",
            "quarantine": "command_channel_lockdown",
            "isolated": "full_isolation_and_revocation",
        }[stage]
        payload = {
            "time": _utc_now().isoformat(),
            "identity": identity,
            "stage": stage,
            "action": action_msg,
        }
        self._actions.append(payload)
        level = "critical" if stage in {"quarantine", "isolated"} else "warning"
        return [Event(level=level, message=f"Autonomous defense action: {action_msg} for {identity}")]

    @staticmethod
    def _avg_seconds(values: list[float]) -> float:
        if not values:
            return 0.0
        return round(sum(values) / len(values), 3)
