# Cosmic Sea

Cosmic Sea is a simulation-based Zero Trust cybersecurity framework for satellite communication networks.

## What it does
- Simulates multiple satellites and one ground station exchanging packet-based telemetry and commands.
- Enforces a security layer on every message with:
  - Ed25519 digital signatures (authentication)
  - HMAC-SHA256 (message integrity)
  - Timestamp + nonce checks (replay protection)
  - AES-256-GCM encryption (confidentiality)
- Maintains dynamic trust scores per node based on behavior.
- Detects anomalies such as abnormal command frequency and spoofed identities.
- Automatically isolates malicious satellites when trust falls below threshold.
- Includes attack simulations:
  - Command injection
  - Replay attacks
  - Satellite impersonation
- Provides a mission control dashboard showing nodes, trust scores, alerts, and blocked devices.

## Project structure
- `app.py` - Flask entrypoint and API routes.
- `cosmic_sea/security.py` - Zero Trust cryptographic validation.
- `cosmic_sea/trust.py` - Dynamic trust scoring and isolation policy.
- `cosmic_sea/simulator.py` - Network + attack simulation engine.
- `templates/index.html` - Mission control dashboard UI.

## Run
```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Notes
- This is a security simulation for education/testing, not flight-certified spacecraft software.
