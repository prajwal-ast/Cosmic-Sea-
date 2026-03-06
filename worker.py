from __future__ import annotations

import os
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests


def _satellite_ids() -> list[str]:
    value = os.getenv("SATELLITE_IDS", "SAT-01,SAT-02,SAT-03,SAT-04,SAT-05,SAT-06")
    return [x.strip() for x in value.split(",") if x.strip()]


API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:5000")
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "")
PUSH_INTERVAL = float(os.getenv("WORKER_PUSH_INTERVAL", "1.0"))
SOURCE_MODE = os.getenv("REAL_SOURCE_MODE", "stub")
WORKER_HEALTH_PORT = int(os.getenv("PORT", "8080"))
WORKER_HEALTHCHECK = os.getenv("WORKER_HEALTHCHECK", "true").strip().lower() in {"1", "true", "yes", "on"}
MAX_CYCLES = int(os.getenv("WORKER_MAX_CYCLES", "0"))


def _headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if INGEST_TOKEN:
        headers["X-Ingest-Token"] = INGEST_TOKEN
    return headers


def _send(payload: dict) -> None:
    url = f"{API_BASE_URL.rstrip('/')}/api/ingest"
    resp = requests.post(url, json=payload, headers=_headers(), timeout=5)
    if resp.status_code >= 300:
        print(f"ingest failed ({resp.status_code}): {resp.text}")


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path not in {"/", "/healthz"}:
            self.send_response(404)
            self.end_headers()
            return

        body = b'{"status":"ok","service":"worker"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        return


def _run_health_server() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", WORKER_HEALTH_PORT), _HealthHandler)
    print(f"worker health server listening on :{WORKER_HEALTH_PORT}")
    server.serve_forever()


def main() -> None:
    sats = _satellite_ids()
    print(f"worker started | mode={SOURCE_MODE} | target={API_BASE_URL} | sats={len(sats)}")
    if WORKER_HEALTHCHECK:
        t = threading.Thread(target=_run_health_server, daemon=True)
        t.start()

    cycles = 0
    while True:
        try:
            for sat in sats:
                telemetry = {
                    "kind": "telemetry",
                    "satellite_id": sat,
                    "battery": random.uniform(52.0, 99.0),
                    "temp_c": random.uniform(-35.0, 46.0),
                }
                _send(telemetry)

            if random.random() < 0.35:
                cmd = {
                    "kind": "command",
                    "satellite_id": random.choice(sats),
                    "command": random.choice(["ADJUST_ORBIT", "SYNC_CLOCK", "CALIBRATE_SENSOR"]),
                    "delta": random.randint(-2, 2),
                }
                _send(cmd)
        except requests.RequestException as exc:
            print(f"worker network error: {exc}")

        cycles += 1
        if MAX_CYCLES > 0 and cycles >= MAX_CYCLES:
            print("worker exiting after max cycles")
            return
        time.sleep(PUSH_INTERVAL)


if __name__ == "__main__":
    main()
