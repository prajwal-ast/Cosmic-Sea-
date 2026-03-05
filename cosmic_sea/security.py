from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import SecurityConfig
from .models import MessagePacket, VerificationResult


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _link_id(identity_a: str, identity_b: str) -> str:
    a, b = sorted((identity_a, identity_b))
    return f"{a}<->{b}"


@dataclass
class LinkKeyMaterial:
    epoch: int
    created_at: datetime
    aes_key: bytes
    hmac_key: bytes
    revoked: bool = False


class KeyRegistry:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._signing_keys: dict[str, Ed25519PrivateKey] = {}
        self._verify_keys: dict[str, Ed25519PublicKey] = {}
        self._revoked_identities: set[str] = set()
        self._link_epochs: dict[str, int] = {}
        self._link_keys: dict[str, dict[int, LinkKeyMaterial]] = defaultdict(dict)

    def register_identity(self, identity: str) -> None:
        private_key = Ed25519PrivateKey.generate()
        self._signing_keys[identity] = private_key
        self._verify_keys[identity] = private_key.public_key()

    def revoke_identity(self, identity: str) -> None:
        self._revoked_identities.add(identity)

    def is_revoked(self, identity: str) -> bool:
        return identity in self._revoked_identities

    def has_identity(self, identity: str) -> bool:
        return identity in self._verify_keys

    def ensure_link(self, identity_a: str, identity_b: str) -> str:
        lid = _link_id(identity_a, identity_b)
        if lid not in self._link_epochs:
            self._link_epochs[lid] = 1
            self._link_keys[lid][1] = self._new_key_material(1)
        return lid

    def active_epoch(self, identity_a: str, identity_b: str) -> int:
        lid = self.ensure_link(identity_a, identity_b)
        self._rotate_if_needed(lid)
        return self._link_epochs[lid]

    def link_material(self, identity_a: str, identity_b: str, epoch: int) -> LinkKeyMaterial | None:
        lid = self.ensure_link(identity_a, identity_b)
        self._rotate_if_needed(lid)
        return self._link_keys[lid].get(epoch)

    def rotate_link(self, identity_a: str, identity_b: str) -> int:
        lid = self.ensure_link(identity_a, identity_b)
        next_epoch = self._link_epochs[lid] + 1
        self._link_epochs[lid] = next_epoch
        self._link_keys[lid][next_epoch] = self._new_key_material(next_epoch)
        self._trim_old_epochs(lid)
        return next_epoch

    def sign(self, identity: str, payload: bytes) -> bytes:
        return self._signing_keys[identity].sign(payload)

    def verify_signature(self, identity: str, payload: bytes, signature: bytes) -> bool:
        try:
            self._verify_keys[identity].verify(signature, payload)
            return True
        except InvalidSignature:
            return False

    def compute_hmac(self, key: bytes, payload: bytes) -> bytes:
        return hmac.new(key, payload, hashlib.sha256).digest()

    def verify_hmac(self, key: bytes, payload: bytes, digest: bytes) -> bool:
        expected = self.compute_hmac(key, payload)
        return hmac.compare_digest(expected, digest)

    def encrypt(self, key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
        return AESGCM(key).encrypt(nonce, plaintext, None)

    def decrypt(self, key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    def export_public_key(self, identity: str) -> str:
        key = self._verify_keys[identity]
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def _rotate_if_needed(self, link_id: str) -> None:
        active_epoch = self._link_epochs[link_id]
        current = self._link_keys[link_id][active_epoch]
        age = (_utc_now() - current.created_at).total_seconds()
        if age >= self.config.key_rotation_interval_seconds:
            next_epoch = active_epoch + 1
            self._link_epochs[link_id] = next_epoch
            self._link_keys[link_id][next_epoch] = self._new_key_material(next_epoch)
            self._trim_old_epochs(link_id)

    def _trim_old_epochs(self, link_id: str) -> None:
        max_epochs = self.config.max_link_epochs
        epochs = sorted(self._link_keys[link_id].keys())
        for epoch in epochs[:-max_epochs]:
            del self._link_keys[link_id][epoch]

    @staticmethod
    def _new_key_material(epoch: int) -> LinkKeyMaterial:
        return LinkKeyMaterial(
            epoch=epoch,
            created_at=_utc_now(),
            aes_key=AESGCM.generate_key(bit_length=256),
            hmac_key=secrets.token_bytes(32),
        )


class ZeroTrustSecurityLayer:
    def __init__(self, keys: KeyRegistry, config: SecurityConfig) -> None:
        self.keys = keys
        self.config = config
        self._seen_nonces: dict[str, dict[str, datetime]] = defaultdict(dict)
        self._message_times: dict[str, deque[datetime]] = defaultdict(deque)

    def issue_packet(
        self,
        sender_id: str,
        receiver_id: str,
        payload: dict[str, Any],
        timestamp_override: str | None = None,
    ) -> MessagePacket:
        timestamp = timestamp_override or _utc_now().isoformat()
        nonce_bytes = secrets.token_bytes(12)
        nonce = base64.b64encode(nonce_bytes).decode("utf-8")

        epoch = self.keys.active_epoch(sender_id, receiver_id)
        material = self.keys.link_material(sender_id, receiver_id, epoch)
        if material is None:
            raise RuntimeError("No key material for link")

        ciphertext = self.keys.encrypt(material.aes_key, _canonical_json(payload), nonce_bytes)
        b64_ciphertext = base64.b64encode(ciphertext).decode("utf-8")

        signed_fields = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "key_epoch": epoch,
            "timestamp": timestamp,
            "nonce": nonce,
            "ciphertext": b64_ciphertext,
        }
        signing_blob = _canonical_json(signed_fields)
        signature = base64.b64encode(self.keys.sign(sender_id, signing_blob)).decode("utf-8")
        digest = base64.b64encode(self.keys.compute_hmac(material.hmac_key, signing_blob)).decode("utf-8")

        return MessagePacket(
            sender_id=sender_id,
            receiver_id=receiver_id,
            key_epoch=epoch,
            timestamp=timestamp,
            nonce=nonce,
            ciphertext=b64_ciphertext,
            signature=signature,
            hmac_tag=digest,
        )

    def verify_packet(self, packet: MessagePacket, expected_receiver: str | None = None) -> VerificationResult:
        if expected_receiver is not None and packet.receiver_id != expected_receiver:
            return VerificationResult(False, "receiver_mismatch")

        if not self.keys.has_identity(packet.sender_id):
            return VerificationResult(False, "unknown_identity")

        if self.keys.is_revoked(packet.sender_id):
            return VerificationResult(False, "identity_revoked")

        material = self.keys.link_material(packet.sender_id, packet.receiver_id, packet.key_epoch)
        if material is None or material.revoked:
            return VerificationResult(False, "key_epoch_invalid")

        parsed_ts = self._parse_ts(packet.timestamp)
        if parsed_ts is None:
            return VerificationResult(False, "bad_timestamp")

        now = _utc_now()
        if abs((now - parsed_ts).total_seconds()) > self.config.allowed_skew_seconds:
            return VerificationResult(False, "timestamp_skew")

        self._evict_stale_nonces(packet.sender_id, now)
        if packet.nonce in self._seen_nonces[packet.sender_id]:
            return VerificationResult(False, "replay_detected")

        signed_fields = {
            "sender_id": packet.sender_id,
            "receiver_id": packet.receiver_id,
            "key_epoch": packet.key_epoch,
            "timestamp": packet.timestamp,
            "nonce": packet.nonce,
            "ciphertext": packet.ciphertext,
        }
        signing_blob = _canonical_json(signed_fields)

        try:
            signature = base64.b64decode(packet.signature)
            digest = base64.b64decode(packet.hmac_tag)
        except Exception:
            return VerificationResult(False, "encoding_error")

        if not self.keys.verify_signature(packet.sender_id, signing_blob, signature):
            return VerificationResult(False, "signature_invalid")

        if not self.keys.verify_hmac(material.hmac_key, signing_blob, digest):
            return VerificationResult(False, "hmac_invalid")

        try:
            nonce_bytes = base64.b64decode(packet.nonce)
            ciphertext = base64.b64decode(packet.ciphertext)
            plaintext = self.keys.decrypt(material.aes_key, ciphertext, nonce_bytes)
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception:
            return VerificationResult(False, "decryption_failed")

        self._seen_nonces[packet.sender_id][packet.nonce] = now
        self._message_times[packet.sender_id].append(now)
        return VerificationResult(True, "ok", payload)

    def detect_abnormal_frequency(self, sender_id: str, limit: int) -> tuple[bool, float]:
        now = _utc_now()
        window = self.config.frequency_window_seconds
        q = self._message_times[sender_id]
        while q and (now - q[0]).total_seconds() > window:
            q.popleft()

        count = len(q)
        if count <= limit:
            return False, 0.0

        confidence = min(1.0, (count - limit) / max(1, limit))
        return True, confidence

    def _evict_stale_nonces(self, sender_id: str, now: datetime) -> None:
        ttl = self.config.nonce_ttl_seconds
        stale = [
            nonce
            for nonce, seen_at in self._seen_nonces[sender_id].items()
            if (now - seen_at).total_seconds() > ttl
        ]
        for nonce in stale:
            del self._seen_nonces[sender_id][nonce]

    @staticmethod
    def _parse_ts(ts: str) -> datetime | None:
        try:
            parsed = datetime.fromisoformat(ts)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None
