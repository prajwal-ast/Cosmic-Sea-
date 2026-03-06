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

## 6. Autonomous Cyber Defense System
- `cosmic_sea/defense_policy.py` implements an autonomous detect-decide-respond controller.
- Violations are ingested as incidents and auto-mapped to defense actions by trust stage:
  - `monitor` -> raise observation level
  - `throttle` -> adaptive rate limiting
  - `quarantine` -> command channel lockdown
  - `isolated` -> full isolation + identity revocation
- Closed-loop KPIs are computed live:
  - `MTTD` (mean time to defensive action)
  - `MTTC` (mean time to containment)
  - `MTTR` (mean time to incident resolution)
  - containment rate and action counters

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
- `cosmic_sea/defense_policy.py` - autonomous cyber defense decision engine.
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

## Deployment (Railway Recommended)
### 1) Deploy API service
- Use this repo as Railway service source.
- Set env vars:
  - `SERVICE_ROLE=api`
  - `SIM_MODE=false` for external ingest mode (or `true` for built-in simulation mode)
  - `INGEST_TOKEN=<strong-random-token>`
  - `CORS_ORIGIN=*` (or your Vercel domain)
- Railway will use `Dockerfile` + `start.sh`.

### 2) Deploy worker service (same repo, second service)
- Create another Railway service from the same repo.
- Set env vars:
  - `SERVICE_ROLE=worker`
  - `API_BASE_URL=https://<your-api-domain>`
  - `INGEST_TOKEN=<same-token-as-api>`
  - `SATELLITE_IDS=SAT-01,SAT-02,SAT-03,SAT-04,SAT-05,SAT-06`
  - `WORKER_PUSH_INTERVAL=1.0`
- Worker exposes health endpoints on `PORT`:
  - `/`
  - `/healthz`
- Set worker healthcheck path to `/healthz` (or `/`).
- This worker posts external telemetry/command events to `POST /api/ingest`.

### 3) Real-time dashboard
- Dashboard reads real-time state from:
  - `GET /api/state`
  - `GET /api/stream` (SSE, real-time push)

## Optional Vercel Frontend
- You can host only the frontend on Vercel and point it to Railway API.
- Before loading dashboard, set:
  - `window.COSMIC_API_BASE = \"https://<railway-api-domain>\"`
- API CORS must allow your Vercel domain (`CORS_ORIGIN`).

## Ingest API
- Endpoint: `POST /api/ingest`
- Auth: `Authorization: Bearer <INGEST_TOKEN>` or header `X-Ingest-Token`.

### Telemetry payload
```json
{
  "kind": "telemetry",
  "satellite_id": "SAT-01",
  "battery": 88.5,
  "temp_c": 21.7
}
```

### Command payload
```json
{
  "kind": "command",
  "satellite_id": "SAT-01",
  "command": "ADJUST_ORBIT",
  "delta": 1
}
```

## Real Satellite Data Adapter Path
- Replace `worker.py` stub generator with your real feed client (ground-station bridge, MQTT, Kafka, SDR decoder, provider API).
- Keep the output contract as `POST /api/ingest` so the Zero Trust and autonomous defense pipeline remains unchanged.

## Disclaimer
This is a cybersecurity simulation prototype for research/demo use, not flight-certified mission software.
