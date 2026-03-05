from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityConfig:
    allowed_skew_seconds: int = 8
    nonce_ttl_seconds: int = 30
    frequency_window_seconds: int = 8
    satellite_freq_limit: int = 7
    ground_freq_limit: int = 12

    trust_bonus_valid: float = 0.4
    trust_decay_minor: float = 6.0
    trust_decay_major: float = 14.0
    trust_monitor_threshold: float = 80.0
    trust_throttle_threshold: float = 65.0
    trust_quarantine_threshold: float = 50.0
    trust_isolate_threshold: float = 35.0

    throttle_drop_ratio: float = 0.45

    key_rotation_interval_seconds: int = 20
    max_link_epochs: int = 3

    base_latency_ms: int = 120
    jitter_ms: int = 70
    packet_loss_rate: float = 0.06
    bit_error_rate: float = 0.05
    clock_drift_max_ms: int = 2200
    visibility_window_ticks: int = 12
    visibility_gap_ticks: int = 4

    ai_warmup_samples: int = 12
    ai_history_size: int = 80
    ai_anomaly_threshold: float = 0.72
