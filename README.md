# Cosmic Sea

Cosmic Sea is a simulation-based Zero Trust security framework for satellite communication networks, designed as a pre-prototype for TT&C security experiments.

## 1. Mission Scope
- **Primary use-case:** protection of command and telemetry exchange between LEO satellites and rotating ground stations.
- **Network model:** packetized links with intermittent visibility, clock skew, packet loss, jitter, and link corruption.
- **Security objective:** every packet is explicitly authenticated, integrity-checked, replay-checked, and encrypted before acceptance.
- **Operational objective:** detect anomalous behavior and enforce staged containment (`monitor -> throttle -> quarantine -> isolate`).

## 2. Threat Model
### Assets
- Command channel integrity.
- Telemetry authenticity.
- Identity and session key material.
- Mission continuity (availability + safe isolation).

### Trust boundaries
- Satellite nodes.
- Ground station nodes.
- Network transport channel (assumed hostile).
- Mission control policy engine.

### Adversary capabilities (simulated)
- Packet replay from captured traffic.
- Command injection with forged fields.
- Satellite impersonation with mismatched identity/signature.
- Channel corruption (bit flips), timing manipulation, and opportunistic link abuse.

### Control mapping
- **Spoofing/Impersonation** -> Ed25519 signature verification, identity revocation.
- **Tampering/MITM** -> HMAC-SHA256 per-link key-epoch material.
- **Replay** -> timestamp skew checks + nonce cache + TTL.
- **Key compromise window** -> automatic link key rotation + bounded epoch retention.
- **Behavioral abuse** -> mission-aware trust scoring and staged response policy.

## 3. Security Architecture Updates
- Long-term identity signing keys per node.
- Link-specific key schedule (AES-256-GCM + HMAC keys) with epoch rotation.
- Packet now carries `key_epoch`; receiver verifies epoch validity.
- Identity revocation and post-isolation cryptographic blocking.

## 4. Network Realism Updates
- Configurable base latency + jitter.
- Probabilistic packet loss.
- Bit error injection (ciphertext/HMAC/signature/nonce corruption).
- Per-node clock drift used in packet timestamps.
- Satellite-ground visibility windows.
- Ground-station handover between `GROUND-ALPHA` and `GROUND-BETA`.

## 5. Mission-Aware Trust Engine Updates
- Role-aware scoring (`satellite`, `ground_station`, `external`).
- Explainable violations with confidence score in alerts.
- Frequency baselines split by role.
- AI anomaly detector (unsupervised online model) over per-node behavioral features.
- Staged policy actions:
  - `monitor`: increased scrutiny.
  - `throttle`: probabilistic transmission drop.
  - `quarantine`: telemetry-only transmissions.
  - `isolate`: node blocked and identity revoked.

## Attack Simulation
- Command injection.
- Replay attack.
- Satellite impersonation.

## AI Anomaly Detection
- `cosmic_sea/anomaly_ai.py` adds a per-identity online anomaly model.
- Features used per packet include:
  - role indicators
  - payload type (`telemetry` vs `command`)
  - receiver class (ground/satellite)
  - telemetry battery and temperature (when present)
  - inter-packet timing delta
- The detector computes multivariate z-score deviation from each node's baseline and outputs:
  - anomaly score
  - anomaly confidence (`0..1`)
- High-confidence anomalies automatically reduce trust and can trigger quarantine/isolation.

## Project structure
- `app.py` - Flask entrypoint and API routes.
- `cosmic_sea/security.py` - cryptography and key lifecycle.
- `cosmic_sea/trust.py` - mission-aware trust scoring and staged response.
- `cosmic_sea/simulator.py` - satellite/ground network + attack simulation + impairments.
- `templates/index.html` - mission control dashboard.

## Run
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Disclaimer
This is a cybersecurity simulation prototype for research/demo use, not flight-certified mission software.
