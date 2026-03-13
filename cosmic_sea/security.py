from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import SecurityConfig
from .models import MessagePacket, VerificationResult


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _link_id(identity_a: str, identity_b: str) -> str:
    a, b = sorted((identity_a, identity_b))
    return f"{a}<->{b}"


@dataclass(frozen=True)
class PacketKeyMaterial:
    epoch: int
    aes_key: bytes
    hmac_key: bytes


class KeyRegistry:
    def __init__(self, config: SecurityConfig) -> None:
        self.config = config
        self._signing_keys: dict[str, Ed25519PrivateKey] = {}
        self._verify_keys: dict[str, Ed25519PublicKey] = {}
        self._agreement_keys: dict[str, X25519PrivateKey] = {}
        self._agreement_public_keys: dict[str, X25519PublicKey] = {}
        self._revoked_identities: set[str] = set()
        self._link_epochs: dict[str, int] = {}

    def register_identity(self, identity: str) -> None:
        signing_key = Ed25519PrivateKey.generate()
        agreement_key = X25519PrivateKey.generate()
        self._signing_keys[identity] = signing_key
        self._verify_keys[identity] = signing_key.public_key()
        self._agreement_keys[identity] = agreement_key
        self._agreement_public_keys[identity] = agreement_key.public_key()

    def revoke_identity(self, identity: str) -> None:
        self._revoked_identities.add(identity)

    def is_revoked(self, identity: str) -> bool:
        return identity in self._revoked_identities

    def has_identity(self, identity: str) -> bool:
        return identity in self._verify_keys

    def ensure_link(self, identity_a: str, identity_b: str) -> str:
        link_id = _link_id(identity_a, identity_b)
        self._link_epochs.setdefault(link_id, 0)
        return link_id

    def next_epoch(self, identity_a: str, identity_b: str) -> int:
        link_id = self.ensure_link(identity_a, identity_b)
        self._link_epochs[link_id] += 1
        return self._link_epochs[link_id]

    def sign(self, identity: str, payload: bytes) -> bytes:
        return self._signing_keys[identity].sign(payload)

    def verify_signature(self, identity: str, payload: bytes, signature: bytes) -> bool:
        try:
            self._verify_keys[identity].verify(signature, payload)
            return True
        except InvalidSignature:
            return False

    def agreement_public_key_b64(self, identity: str) -> str:
        raw = self._agreement_public_keys[identity].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("utf-8")

    def derive_sender_packet_material(
        self,
        sender_id: str,
        receiver_id: str,
        epoch: int,
        packet_id: str,
        timestamp: str,
        satellite_position: str,
    ) -> tuple[PacketKeyMaterial, str]:
        ephemeral_private = X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        receiver_public = self._agreement_public_keys[receiver_id]
        static_shared = self._agreement_keys[sender_id].exchange(receiver_public)
        ephemeral_shared = ephemeral_private.exchange(receiver_public)
        material = self._derive_packet_material(
            sender_id=sender_id,
            receiver_id=receiver_id,
            static_shared=static_shared,
            epoch=epoch,
            packet_id=packet_id,
            timestamp=timestamp,
            satellite_position=satellite_position,
            ephemeral_shared=ephemeral_shared,
        )
        return material, base64.b64encode(ephemeral_public).decode("utf-8")

    def derive_receiver_packet_material(
        self,
        sender_id: str,
        receiver_id: str,
        epoch: int,
        packet_id: str,
        timestamp: str,
        satellite_position: str,
        ephemeral_public_key: str,
    ) -> PacketKeyMaterial | None:
        try:
            ephemeral_public = X25519PublicKey.from_public_bytes(base64.b64decode(ephemeral_public_key))
        except Exception:
            return None

        receiver_private = self._agreement_keys[receiver_id]
        static_shared = receiver_private.exchange(self._agreement_public_keys[sender_id])
        ephemeral_shared = receiver_private.exchange(ephemeral_public)
        return self._derive_packet_material(
            sender_id=sender_id,
            receiver_id=receiver_id,
            static_shared=static_shared,
            epoch=epoch,
            packet_id=packet_id,
            timestamp=timestamp,
            satellite_position=satellite_position,
            ephemeral_shared=ephemeral_shared,
        )

    @staticmethod
    def compute_hmac(key: bytes, payload: bytes) -> bytes:
        return hmac.new(key, payload, hashlib.sha256).digest()

    def verify_hmac(self, key: bytes, payload: bytes, digest: bytes) -> bool:
        expected = self.compute_hmac(key, payload)
        return hmac.compare_digest(expected, digest)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
        return AESGCM(key).encrypt(nonce, plaintext, None)

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    def _derive_packet_material(
        self,
        sender_id: str,
        receiver_id: str,
        static_shared: bytes,
        epoch: int,
        packet_id: str,
        timestamp: str,
        satellite_position: str,
        ephemeral_shared: bytes,
    ) -> PacketKeyMaterial:
        ratchet_seed = hmac.new(static_shared, f"epoch:{epoch}".encode("utf-8"), hashlib.sha256).digest()
        info = "|".join(
            [
                "cosmic-sea-hybrid-v2",
                str(epoch),
                packet_id,
                timestamp,
                satellite_position,
            ]
        ).encode("utf-8")
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=ratchet_seed,
            info=info,
        ).derive(ephemeral_shared + static_shared)
        return PacketKeyMaterial(epoch=epoch, aes_key=derived[:32], hmac_key=derived[32:])


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
        satellite_position: str,
        packet_id: str | None = None,
        timestamp_override: str | None = None,
    ) -> MessagePacket:
        timestamp = timestamp_override or _utc_now().isoformat()
        nonce_bytes = secrets.token_bytes(12)
        nonce = base64.b64encode(nonce_bytes).decode("utf-8")
        packet_id = packet_id or secrets.token_hex(8)
        epoch = self.keys.next_epoch(sender_id, receiver_id)
        material, ephemeral_public_key = self.keys.derive_sender_packet_material(
            sender_id=sender_id,
            receiver_id=receiver_id,
            epoch=epoch,
            packet_id=packet_id,
            timestamp=timestamp,
            satellite_position=satellite_position,
        )

        ciphertext = self.keys.encrypt(material.aes_key, _canonical_json(payload), nonce_bytes)
        b64_ciphertext = base64.b64encode(ciphertext).decode("utf-8")
        signed_fields = self._signed_fields(
            sender_id=sender_id,
            receiver_id=receiver_id,
            key_epoch=epoch,
            packet_id=packet_id,
            timestamp=timestamp,
            satellite_position=satellite_position,
            nonce=nonce,
            ephemeral_public_key=ephemeral_public_key,
            ciphertext=b64_ciphertext,
        )
        signing_blob = _canonical_json(signed_fields)
        signature = base64.b64encode(self.keys.sign(sender_id, signing_blob)).decode("utf-8")
        digest = base64.b64encode(self.keys.compute_hmac(material.hmac_key, signing_blob)).decode("utf-8")

        return MessagePacket(
            sender_id=sender_id,
            receiver_id=receiver_id,
            key_epoch=epoch,
            packet_id=packet_id,
            timestamp=timestamp,
            satellite_position=satellite_position,
            nonce=nonce,
            ephemeral_public_key=ephemeral_public_key,
            ciphertext=b64_ciphertext,
            signature=signature,
            hmac_tag=digest,
        )

    def verify_packet(self, packet: MessagePacket, expected_receiver: str | None = None) -> VerificationResult:
        if expected_receiver is not None and packet.receiver_id != expected_receiver:
            return VerificationResult(False, "receiver_mismatch")
        if not self.keys.has_identity(packet.sender_id):
            return VerificationResult(False, "unknown_identity")
        if not self.keys.has_identity(packet.receiver_id):
            return VerificationResult(False, "unknown_receiver")
        if self.keys.is_revoked(packet.sender_id):
            return VerificationResult(False, "identity_revoked")
        if packet.key_epoch <= 0 or not packet.packet_id:
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

        material = self.keys.derive_receiver_packet_material(
            sender_id=packet.sender_id,
            receiver_id=packet.receiver_id,
            epoch=packet.key_epoch,
            packet_id=packet.packet_id,
            timestamp=packet.timestamp,
            satellite_position=packet.satellite_position,
            ephemeral_public_key=packet.ephemeral_public_key,
        )
        if material is None:
            return VerificationResult(False, "key_exchange_invalid")

        signed_fields = self._signed_fields(
            sender_id=packet.sender_id,
            receiver_id=packet.receiver_id,
            key_epoch=packet.key_epoch,
            packet_id=packet.packet_id,
            timestamp=packet.timestamp,
            satellite_position=packet.satellite_position,
            nonce=packet.nonce,
            ephemeral_public_key=packet.ephemeral_public_key,
            ciphertext=packet.ciphertext,
        )
        signing_blob = _canonical_json(signed_fields)

        try:
            signature = base64.b64decode(packet.signature)
            digest = base64.b64decode(packet.hmac_tag)
            nonce_bytes = base64.b64decode(packet.nonce)
            ciphertext = base64.b64decode(packet.ciphertext)
        except Exception:
            return VerificationResult(False, "encoding_error")

        if not self.keys.verify_signature(packet.sender_id, signing_blob, signature):
            return VerificationResult(False, "signature_invalid")
        if not self.keys.verify_hmac(material.hmac_key, signing_blob, digest):
            return VerificationResult(False, "hmac_invalid")

        try:
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

    @staticmethod
    def _signed_fields(
        sender_id: str,
        receiver_id: str,
        key_epoch: int,
        packet_id: str,
        timestamp: str,
        satellite_position: str,
        nonce: str,
        ephemeral_public_key: str,
        ciphertext: str,
    ) -> dict[str, Any]:
        return {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "key_epoch": key_epoch,
            "packet_id": packet_id,
            "timestamp": timestamp,
            "satellite_position": satellite_position,
            "nonce": nonce,
            "ephemeral_public_key": ephemeral_public_key,
            "ciphertext": ciphertext,
        }
