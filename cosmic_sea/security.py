from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import SecurityConfig
from .models import MessagePacket, VerificationResult


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


class KeyRegistry:
    def __init__(self) -> None:
        self._signing_keys: dict[str, Ed25519PrivateKey] = {}
        self._verify_keys: dict[str, Ed25519PublicKey] = {}
        self._hmac_keys: dict[str, bytes] = {}
        self._aes_keys: dict[str, bytes] = {}

    def register_identity(self, identity: str) -> None:
        private_key = Ed25519PrivateKey.generate()
        self._signing_keys[identity] = private_key
        self._verify_keys[identity] = private_key.public_key()
        self._hmac_keys[identity] = secrets.token_bytes(32)
        self._aes_keys[identity] = AESGCM.generate_key(bit_length=256)

    def has_identity(self, identity: str) -> bool:
        return identity in self._verify_keys

    def sign(self, identity: str, payload: bytes) -> bytes:
        return self._signing_keys[identity].sign(payload)

    def verify(self, identity: str, payload: bytes, signature: bytes) -> bool:
        try:
            self._verify_keys[identity].verify(signature, payload)
            return True
        except InvalidSignature:
            return False

    def hmac_digest(self, identity: str, payload: bytes) -> bytes:
        return hmac.new(self._hmac_keys[identity], payload, hashlib.sha256).digest()

    def verify_hmac(self, identity: str, payload: bytes, digest: bytes) -> bool:
        expected = self.hmac_digest(identity, payload)
        return hmac.compare_digest(expected, digest)

    def encrypt_for(self, identity: str, plaintext: bytes, nonce: bytes) -> bytes:
        return AESGCM(self._aes_keys[identity]).encrypt(nonce, plaintext, None)

    def decrypt_for(self, identity: str, ciphertext: bytes, nonce: bytes) -> bytes:
        return AESGCM(self._aes_keys[identity]).decrypt(nonce, ciphertext, None)

    def export_public_key(self, identity: str) -> str:
        key = self._verify_keys[identity]
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")


class ZeroTrustSecurityLayer:
    def __init__(self, keys: KeyRegistry, config: SecurityConfig) -> None:
        self.keys = keys
        self.config = config
        self._seen_nonces: dict[str, dict[str, datetime]] = defaultdict(dict)
        self._message_times: dict[str, deque[datetime]] = defaultdict(deque)

    def issue_packet(self, sender_id: str, receiver_id: str, payload: dict[str, Any]) -> MessagePacket:
        timestamp = _utc_now().isoformat()
        nonce_bytes = secrets.token_bytes(12)
        nonce = base64.b64encode(nonce_bytes).decode("utf-8")

        ciphertext = self.keys.encrypt_for(sender_id, _canonical_json(payload), nonce_bytes)
        b64_ciphertext = base64.b64encode(ciphertext).decode("utf-8")

        signed_fields = {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "ciphertext": b64_ciphertext,
        }
        signing_blob = _canonical_json(signed_fields)
        signature = base64.b64encode(self.keys.sign(sender_id, signing_blob)).decode("utf-8")
        digest = base64.b64encode(self.keys.hmac_digest(sender_id, signing_blob)).decode("utf-8")

        return MessagePacket(
            sender_id=sender_id,
            receiver_id=receiver_id,
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

        if not self.keys.verify(packet.sender_id, signing_blob, signature):
            return VerificationResult(False, "signature_invalid")

        if not self.keys.verify_hmac(packet.sender_id, signing_blob, digest):
            return VerificationResult(False, "hmac_invalid")

        try:
            nonce_bytes = base64.b64decode(packet.nonce)
            ciphertext = base64.b64decode(packet.ciphertext)
            plaintext = self.keys.decrypt_for(packet.sender_id, ciphertext, nonce_bytes)
            payload = json.loads(plaintext.decode("utf-8"))
        except Exception:
            return VerificationResult(False, "decryption_failed")

        self._seen_nonces[packet.sender_id][packet.nonce] = now
        self._message_times[packet.sender_id].append(now)
        return VerificationResult(True, "ok", payload)

    def detect_abnormal_frequency(self, sender_id: str) -> bool:
        now = _utc_now()
        window = self.config.frequency_window_seconds
        q = self._message_times[sender_id]
        while q and (now - q[0]).total_seconds() > window:
            q.popleft()
        return len(q) > self.config.frequency_limit

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
