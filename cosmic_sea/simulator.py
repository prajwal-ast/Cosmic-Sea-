from __future__ import annotations

import random
import threading
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any

from .anomaly_ai import AIAnomalyDetector
from .config import SecurityConfig
from .defense_policy import AutonomousDefenseSystem
from .models import Event, MessagePacket
from .nodes import GroundStation, SatelliteNode
from .security import KeyRegistry, ZeroTrustSecurityLayer
from .trust import TrustEngine


class CosmicSeaSimulator:
    def __init__(self, num_satellites: int = 5, tick_interval: float = 1.0, auto_simulation: bool = True) -> None:
        self.config = SecurityConfig()
        self.keys = KeyRegistry(self.config)
        self.security = ZeroTrustSecurityLayer(self.keys, self.config)
        self.trust = TrustEngine(self.config)
        self.ai = AIAnomalyDetector(self.config)

        self.ground_stations = [GroundStation("GROUND-ALPHA"), GroundStation("GROUND-BETA")]
        self.active_ground_idx = 0
        self.satellites = [SatelliteNode(f"SAT-{i+1:02d}") for i in range(num_satellites)]
        self.tick_interval = tick_interval
        self.auto_simulation = auto_simulation

        self._events: list[Event] = []
        self._blocked: set[str] = set()
        self.defense = AutonomousDefenseSystem(self.config, self.trust, self.keys, self._blocked)
        self._captured_packet: MessagePacket | None = None
        self._clock_offsets_ms: dict[str, int] = {}
        self._in_flight: list[tuple[float, MessagePacket, str]] = []
        self._tick = 0

        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

        self._bootstrap_identities()

    @property
    def active_ground(self) -> GroundStation:
        return self.ground_stations[self.active_ground_idx]

    def _bootstrap_identities(self) -> None:
        for gs in self.ground_stations:
            self.keys.register_identity(gs.station_id)
            self.trust.ensure_identity(gs.station_id, role=gs.role)
            self.ai.ensure_identity(gs.station_id)
            self.defense.ensure_identity(gs.station_id)
            self._clock_offsets_ms[gs.station_id] = random.randint(-250, 250)

        for sat in self.satellites:
            self.keys.register_identity(sat.satellite_id)
            self.trust.ensure_identity(sat.satellite_id, role=sat.role)
            self.ai.ensure_identity(sat.satellite_id)
            self.defense.ensure_identity(sat.satellite_id)
            self._clock_offsets_ms[sat.satellite_id] = random.randint(
                -self.config.clock_drift_max_ms,
                self.config.clock_drift_max_ms,
            )
            sat.orbital_phase_deg = random.uniform(0.0, 359.0)

    def start(self) -> None:
        if not self.auto_simulation:
            return
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if not self.auto_simulation:
            return
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            trust_data = self.trust.snapshot()
            blocked = sorted(self._blocked)
            satellites = [
                {
                    "id": sat.satellite_id,
                    "trust": trust_data[sat.satellite_id]["score"],
                    "stage": trust_data[sat.satellite_id]["stage"],
                    "isolated": trust_data[sat.satellite_id]["isolated"],
                    "ai_risk": self.ai.risk_score(sat.satellite_id),
                    "position": self._satellite_position(sat.satellite_id),
                }
                for sat in self.satellites
            ]
            return {
                "time": datetime.now(timezone.utc).isoformat(),
                "mode": "simulation" if self.auto_simulation else "external_ingest",
                "crypto_mode": "hybrid-ecc-aes256gcm-orbit-aware",
                "active_ground_station": self.active_ground.station_id,
                "ground_stations": [gs.station_id for gs in self.ground_stations],
                "satellites": satellites,
                "blocked": blocked,
                "defense_kpis": self.defense.kpis(),
                "alerts": self.trust.all_alerts(limit=30),
                "events": [ev.__dict__ for ev in self._events[-20:]],
            }

    def ingest_external_telemetry(self, satellite_id: str, battery: float, temp_c: float) -> dict[str, str]:
        with self._lock:
            if not any(x.satellite_id == satellite_id for x in self.satellites):
                return {"status": "error", "reason": "unknown_satellite"}

            payload = {
                "type": "telemetry",
                "battery": battery,
                "temp_c": temp_c,
                "source": "external_feed",
            }
            packet = self.security.issue_packet(
                sender_id=satellite_id,
                receiver_id=self.active_ground.station_id,
                payload=payload,
                satellite_position=self._satellite_position(satellite_id),
                timestamp_override=self._clock_time(satellite_id),
            )
            self._process_packet(packet, declared_payload_type="telemetry")
            return {"status": "ok"}

    def ingest_external_command(self, command: str, satellite_id: str, delta: int = 0) -> dict[str, str]:
        with self._lock:
            if not any(x.satellite_id == satellite_id for x in self.satellites):
                return {"status": "error", "reason": "unknown_satellite"}
            if self._is_isolated(satellite_id):
                return {"status": "error", "reason": "satellite_isolated"}

            payload = {"type": "command", "cmd": command, "delta": delta, "source": "external_feed"}
            packet = self.security.issue_packet(
                sender_id=self.active_ground.station_id,
                receiver_id=satellite_id,
                payload=payload,
                satellite_position=self._ground_position(self.active_ground.station_id),
                timestamp_override=self._clock_time(self.active_ground.station_id),
            )
            self._process_packet(packet, declared_payload_type="command")
            return {"status": "ok"}

    def _run_loop(self) -> None:
        while self._running:
            self._simulate_tick()
            time.sleep(self.tick_interval)

    def _simulate_tick(self) -> None:
        with self._lock:
            self._tick += 1
            self._maybe_handover_ground_station()
            self._advance_orbits()

            for sat in self.satellites:
                self._emit_telemetry(sat.satellite_id)

            if random.random() < 0.85:
                self._send_ground_command(random.choice(self.satellites).satellite_id)

            self._deliver_due_packets()
            self._simulate_attack_cycle()
            self._deliver_due_packets()

    def _emit_telemetry(self, satellite_id: str) -> None:
        sender = satellite_id
        receiver = self.active_ground.station_id
        if self._is_isolated(sender):
            return
        if not self._can_transmit(sender, "telemetry"):
            self._events.append(Event(level="warning", message=f"{sender} transmission suppressed by stage policy"))
            return

        payload = {
            "type": "telemetry",
            "battery": random.randint(55, 100),
            "temp_c": round(random.uniform(-32.0, 44.0), 2),
            "link": f"{sender}->{receiver}",
        }
        packet = self.security.issue_packet(
            sender_id=sender,
            receiver_id=receiver,
            payload=payload,
            satellite_position=self._satellite_position(sender),
            timestamp_override=self._clock_time(sender),
        )
        self._captured_packet = deepcopy(packet)
        self._transmit(packet, "telemetry")

    def _send_ground_command(self, satellite_id: str) -> None:
        sender = self.active_ground.station_id
        receiver = satellite_id
        if self._is_isolated(sender) or self._is_isolated(receiver):
            return
        if not self._can_transmit(sender, "command"):
            self._events.append(Event(level="warning", message=f"{sender} command throttled by trust stage"))
            return

        payload = {
            "type": "command",
            "cmd": random.choice(["ADJUST_ORBIT", "SYNC_CLOCK", "CALIBRATE_SENSOR"]),
            "delta": random.randint(-2, 2),
        }
        packet = self.security.issue_packet(
            sender_id=sender,
            receiver_id=receiver,
            payload=payload,
            satellite_position=self._ground_position(sender),
            timestamp_override=self._clock_time(sender),
        )
        self._transmit(packet, "command")

    def _transmit(self, packet: MessagePacket, payload_type: str) -> None:
        if not self._link_visible(packet.sender_id, packet.receiver_id):
            self._events.append(
                Event(level="warning", message=f"Link unavailable (visibility): {packet.sender_id} -> {packet.receiver_id}")
            )
            return

        if random.random() < self.config.packet_loss_rate:
            self._events.append(Event(level="warning", message=f"Packet loss: {packet.sender_id} -> {packet.receiver_id}"))
            return

        outbound = deepcopy(packet)
        if random.random() < self.config.bit_error_rate:
            outbound = self._corrupt_packet(outbound)
            self._events.append(
                Event(level="warning", message=f"Bit error injected on link: {packet.sender_id} -> {packet.receiver_id}")
            )

        latency_ms = max(10, self.config.base_latency_ms + random.randint(-self.config.jitter_ms, self.config.jitter_ms))
        deliver_at = time.monotonic() + (latency_ms / 1000.0)
        self._in_flight.append((deliver_at, outbound, payload_type))

    def _deliver_due_packets(self) -> None:
        now = time.monotonic()
        due = [item for item in self._in_flight if item[0] <= now]
        self._in_flight = [item for item in self._in_flight if item[0] > now]

        for _, packet, payload_type in due:
            self._process_packet(packet, payload_type)

    def _process_packet(self, packet: MessagePacket, declared_payload_type: str) -> None:
        if not self.trust.has_identity(packet.sender_id):
            self.trust.ensure_identity(packet.sender_id, role="external")
            self.ai.ensure_identity(packet.sender_id)
            self.defense.ensure_identity(packet.sender_id)

        if self._is_isolated(packet.sender_id):
            self._events.append(Event(level="critical", message=f"Blocked packet from isolated {packet.sender_id}"))
            return

        known_receivers = {gs.station_id for gs in self.ground_stations} | {sat.satellite_id for sat in self.satellites}
        if packet.receiver_id not in known_receivers:
            self._apply_violation(packet.sender_id, "unknown_receiver", severity="major", confidence=0.95)
            self._events.append(Event(level="critical", message=f"Rejected packet to unknown receiver {packet.receiver_id}"))
            return

        result = self.security.verify_packet(packet, expected_receiver=None)
        if result.ok:
            payload = result.payload or {}
            payload_type = str(payload.get("type", declared_payload_type))
            role = self.trust.role(packet.sender_id)

            if role == "satellite" and payload_type == "command":
                self._apply_violation(packet.sender_id, "command_origin_violation", severity="major", confidence=0.88)
            elif role == "ground_station" and payload_type == "telemetry":
                self._apply_violation(packet.sender_id, "telemetry_origin_violation", severity="minor", confidence=0.62)
            else:
                self.trust.mark_good(packet.sender_id)
                self._events.extend(self.defense.on_good(packet.sender_id))

            ai_out = self.ai.observe(
                identity=packet.sender_id,
                role=role,
                receiver_id=packet.receiver_id,
                payload_type=payload_type,
                battery=payload.get("battery"),
                temp_c=payload.get("temp_c"),
                timestamp=packet.timestamp,
            )
            if ai_out.is_anomaly:
                severity = "major" if ai_out.confidence >= 0.85 else "minor"
                self._apply_violation(
                    packet.sender_id,
                    f"ai_anomaly(score={ai_out.score:.2f})",
                    severity=severity,
                    confidence=ai_out.confidence,
                )
                self._events.append(
                    Event(
                        level="critical" if severity == "major" else "warning",
                        message=(
                            f"AI anomaly detected for {packet.sender_id}: "
                            f"confidence={ai_out.confidence:.2f}, score={ai_out.score:.2f}"
                        ),
                    )
                )

            limit = self.config.ground_freq_limit if role == "ground_station" else self.config.satellite_freq_limit
            abnormal, confidence = self.security.detect_abnormal_frequency(packet.sender_id, limit=limit)
            if abnormal:
                self._apply_violation(
                    packet.sender_id,
                    "abnormal_command_frequency",
                    severity="minor",
                    confidence=max(0.55, confidence),
                )
                self._events.append(
                    Event(
                        level="warning",
                        message=f"{packet.sender_id} exceeded frequency baseline (confidence={confidence:.2f})",
                    )
                )
            return

        major_reasons = {
            "signature_invalid",
            "hmac_invalid",
            "replay_detected",
            "unknown_identity",
            "identity_revoked",
            "key_epoch_invalid",
            "key_exchange_invalid",
        }
        severity = "major" if result.reason in major_reasons else "minor"
        confidence = 0.95 if severity == "major" else 0.7
        self._apply_violation(packet.sender_id, result.reason, severity=severity, confidence=confidence)
        self._events.append(Event(level="critical", message=f"Rejected packet from {packet.sender_id}: {result.reason}"))

    def _apply_violation(self, identity: str, reason: str, severity: str, confidence: float) -> None:
        self._events.extend(self.defense.on_violation(identity, reason, severity=severity, confidence=confidence))

    def _can_transmit(self, identity: str, payload_type: str) -> bool:
        return self.trust.can_transmit(identity, payload_type)

    def _is_isolated(self, identity: str) -> bool:
        return self.trust.get_state(identity).isolated

    def _simulate_attack_cycle(self) -> None:
        attack_roll = random.random()
        if attack_roll < 0.34:
            self._attack_command_injection()
        elif attack_roll < 0.67:
            self._attack_replay()
        else:
            self._attack_impersonation()

    def _attack_command_injection(self) -> None:
        target = random.choice(self.satellites).satellite_id
        fake = MessagePacket(
            sender_id="SAT-FAKE",
            receiver_id=target,
            key_epoch=1,
            packet_id="forged-packet",
            timestamp=datetime.now(timezone.utc).isoformat(),
            satellite_position="LEO:0.0,0.0,0.0",
            nonce="badnonce",
            ephemeral_public_key="badkey",
            ciphertext="inject_payload",
            signature="invalidsig",
            hmac_tag="invalidhmac",
        )
        self._process_packet(fake, declared_payload_type="command")
        self._events.append(Event(level="warning", message="Attack simulated: command injection"))

    def _attack_replay(self) -> None:
        if self._captured_packet is None:
            return
        replay_packet = deepcopy(self._captured_packet)
        self._process_packet(replay_packet, declared_payload_type="telemetry")
        self._events.append(Event(level="warning", message="Attack simulated: replay attack"))

    def _attack_impersonation(self) -> None:
        victim = random.choice(self.satellites).satellite_id
        forged = self.security.issue_packet(
            sender_id=self.active_ground.station_id,
            receiver_id=self.active_ground.station_id,
            payload={"type": "command", "cmd": "DISABLE_SAFETY"},
            satellite_position=self._ground_position(self.active_ground.station_id),
            timestamp_override=self._clock_time(self.active_ground.station_id),
        )
        forged.sender_id = victim
        self._process_packet(forged, declared_payload_type="command")
        self._events.append(Event(level="warning", message="Attack simulated: satellite impersonation"))

    def _maybe_handover_ground_station(self) -> None:
        if self._tick % self.config.visibility_window_ticks == 0:
            self.active_ground_idx = (self.active_ground_idx + 1) % len(self.ground_stations)
            self._events.append(Event(level="warning", message=f"Ground handover -> {self.active_ground.station_id}"))

    def _link_visible(self, sender: str, receiver: str) -> bool:
        if sender.startswith("SAT-") and receiver.startswith("GROUND-"):
            sat_index = int(sender.split("-")[1])
            phase = (self._tick + sat_index) % (self.config.visibility_window_ticks + self.config.visibility_gap_ticks)
            return phase < self.config.visibility_window_ticks
        if sender.startswith("GROUND-") and receiver.startswith("SAT-"):
            sat_index = int(receiver.split("-")[1])
            phase = (self._tick + sat_index) % (self.config.visibility_window_ticks + self.config.visibility_gap_ticks)
            return phase < self.config.visibility_window_ticks
        return True

    @staticmethod
    def _corrupt_packet(packet: MessagePacket) -> MessagePacket:
        mutation_target = random.choice(["ciphertext", "hmac_tag", "signature", "nonce"])
        current = getattr(packet, mutation_target)
        if not current:
            current = "x"
        flipped = ("A" if current[0] != "A" else "B") + current[1:]
        setattr(packet, mutation_target, flipped)
        return packet

    def _clock_time(self, identity: str) -> str:
        skew = self._clock_offsets_ms.get(identity, 0)
        dt = datetime.now(timezone.utc) + timedelta(milliseconds=skew)
        return dt.isoformat()

    def _advance_orbits(self) -> None:
        for sat in self.satellites:
            sat.orbital_phase_deg = (sat.orbital_phase_deg + random.uniform(3.5, 9.5)) % 360.0

    def _satellite_position(self, satellite_id: str) -> str:
        sat = next(x for x in self.satellites if x.satellite_id == satellite_id)
        x, y, z = sat.position()
        return f"LEO:{x},{y},{z}"

    @staticmethod
    def _ground_position(station_id: str) -> str:
        anchors = {
            "GROUND-ALPHA": "GROUND:1267.4,6142.2,0.0",
            "GROUND-BETA": "GROUND:-1480.8,6023.6,0.0",
        }
        return anchors.get(station_id, "GROUND:0.0,6371.0,0.0")
