from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityConfig:
    allowed_skew_seconds: int = 8
    nonce_ttl_seconds: int = 30
    trust_decay_minor: float = 7.5
    trust_decay_major: float = 18.0
    trust_bonus_valid: float = 0.75
    isolate_threshold: float = 40.0
    frequency_window_seconds: int = 5
    frequency_limit: int = 5
