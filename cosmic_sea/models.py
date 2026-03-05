from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class MessagePacket:
    sender_id: str
    receiver_id: str
    key_epoch: int
    timestamp: str
    nonce: str
    ciphertext: str
    signature: str
    hmac_tag: str


@dataclass
class Event:
    level: str
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class VerificationResult:
    ok: bool
    reason: str
    payload: dict[str, Any] | None = None
