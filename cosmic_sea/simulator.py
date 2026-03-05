from __future__ import annotations

import random
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from .config import SecurityConfig
from .models import Event, MessagePacket
from .nodes import GroundStation, SatelliteNode
from .security import KeyRegistry, ZeroTrustSecurityLayer
from .trust import TrustEngine


class CosmicSeaSimulator:
    def __init__(self, num_satellites: int = 5, tick_interval: float = 1.2) -> None:
        self.config = SecurityConfig()
        self.keys = KeyRegistry()
        self.security = ZeroTrustSecurityLayer(self.keys, self.config)
        self.trust = TrustEngine(self.config)

        self.ground = GroundStation()
        self.satellites = [SatelliteNode(f"SAT-{i+1:02d}") for i in range(num_satellites)]
        self.tick_interval = tick_interval

        self._events: list[Event] = []
        self._blocked: set[str] = set()
        self._captured_packet: MessagePacket | None = None
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

        self._bootstrap_identities()

    def _bootstrap_identities(self) -> None:
        self.keys.register_identity(self.ground.station_id)
        self.trust.ensure_identity(self.ground.station_id)
        for sat in self.satellites:
            self.keys.register_identity(sat.satellite_id)
            self.trust.ensure_identity(sat.satellite_id)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
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
                    "isolated": trust_data[sat.satellite_id]["isolated"],
                }
                for sat in self.satellites
            ]
            return {
                "time": datetime.now(timezone.utc).isoformat(),
                "ground_station": self.ground.station_id,
                "satellites": satellites,
                "blocked": blocked,
                "alerts": self.trust.all_alerts(limit=25),
                "events": [ev.__dict__ for ev in self._events[-15:]],
            }

    def _run_loop(self) -> None:
        while self._running:
            self._simulate_tick()
            time.sleep(self.tick_interval)

    def _simulate_tick(self) -> None:
        with self._lock:
            for sat in self.satellites:
                if self._is_isolated(sat.satellite_id):
                    continue
                packet = self.security.issue_packet(
                    sender_id=sat.satellite_id,
                    receiver_id=self.ground.station_id,
                    payload={
                        "type": "telemetry",
                        "battery": random.randint(60, 100),
                        "temp_c": round(random.uniform(-25.0, 42.0), 2),
                    },
                )
                self._process_packet(packet)
                self._captured_packet = deepcopy(packet)

            if random.random() < 0.8:
                self._send_ground_command(random.choice(self.satellites).satellite_id)

            attack_roll = random.random()
            if attack_roll < 0.34:
                self._attack_command_injection()
            elif attack_roll < 0.67:
                self._attack_replay()
            else:
                self._attack_impersonation()

    def _send_ground_command(self, satellite_id: str) -> None:
        if self._is_isolated(satellite_id):
            return
        packet = self.security.issue_packet(
            sender_id=self.ground.station_id,
            receiver_id=satellite_id,
            payload={"type": "command", "cmd": "ADJUST_ORBIT", "delta": random.randint(-2, 2)},
        )
        self._process_packet(packet)

    def _process_packet(self, packet: MessagePacket) -> None:
        if not self.trust.has_identity(packet.sender_id):
            self.trust.ensure_identity(packet.sender_id)

        if self._is_isolated(packet.sender_id):
            self._events.append(Event(level="critical", message=f"Blocked packet from isolated {packet.sender_id}"))
            return

        known_receivers = {self.ground.station_id} | {sat.satellite_id for sat in self.satellites}
        if packet.receiver_id not in known_receivers:
            self.trust.mark_major_violation(packet.sender_id, "unknown_receiver")
            self._events.append(Event(level="critical", message=f"Rejected packet to unknown receiver {packet.receiver_id}"))
            return

        result = self.security.verify_packet(packet, expected_receiver=None)
        if result.ok:
            self.trust.mark_good(packet.sender_id)
            if self.security.detect_abnormal_frequency(packet.sender_id):
                self.trust.mark_minor_violation(packet.sender_id, "abnormal command frequency")
                self._events.append(Event(level="warning", message=f"{packet.sender_id} exceeded rate threshold"))
            return

        major_reasons = {"signature_invalid", "hmac_invalid", "replay_detected", "unknown_identity"}
        if result.reason in major_reasons:
            self.trust.mark_major_violation(packet.sender_id, result.reason)
        else:
            self.trust.mark_minor_violation(packet.sender_id, result.reason)
        self._events.append(Event(level="critical", message=f"Rejected packet from {packet.sender_id}: {result.reason}"))

        if self.trust.get_state(packet.sender_id).isolated:
            self._blocked.add(packet.sender_id)
            self._events.append(Event(level="critical", message=f"{packet.sender_id} isolated from network"))

    def _is_isolated(self, identity: str) -> bool:
        return self.trust.get_state(identity).isolated

    def _attack_command_injection(self) -> None:
        target = random.choice(self.satellites).satellite_id
        fake = MessagePacket(
            sender_id="SAT-FAKE",
            receiver_id=target,
            timestamp=datetime.now(timezone.utc).isoformat(),
            nonce="badnonce",
            ciphertext="inject_payload",
            signature="invalidsig",
            hmac_tag="invalidhmac",
        )
        self.trust.ensure_identity("SAT-FAKE")
        self._process_packet(fake)
        self._events.append(Event(level="warning", message="Attack simulated: command injection"))

    def _attack_replay(self) -> None:
        if self._captured_packet is None:
            return
        replay_packet = deepcopy(self._captured_packet)
        self._process_packet(replay_packet)
        self._events.append(Event(level="warning", message="Attack simulated: replay attack"))

    def _attack_impersonation(self) -> None:
        victim = random.choice(self.satellites).satellite_id
        attacker = self.ground.station_id
        forged = self.security.issue_packet(
            sender_id=attacker,
            receiver_id=self.ground.station_id,
            payload={"type": "command", "cmd": "DISABLE_SAFETY"},
        )
        forged.sender_id = victim
        self._process_packet(forged)
        self._events.append(Event(level="warning", message="Attack simulated: satellite impersonation"))
