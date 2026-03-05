from __future__ import annotations

import json
import os
import time
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

from cosmic_sea.simulator import CosmicSeaSimulator


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


SIM_MODE = _env_bool("SIM_MODE", True)
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "")
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "*")

sim = CosmicSeaSimulator(num_satellites=6, tick_interval=1.0, auto_simulation=SIM_MODE)
sim.start()

app = Flask(__name__)


@app.after_request
def add_cors_headers(resp: Response) -> Response:
    resp.headers["Access-Control-Allow-Origin"] = CORS_ORIGIN
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Ingest-Token"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/state")
def state():
    return jsonify(sim.snapshot())


@app.route("/api/stream")
def stream() -> Response:
    def event_stream():
        while True:
            payload = json.dumps(sim.snapshot())
            yield f"data: {payload}\n\n"
            time.sleep(1.0)

    return Response(event_stream(), mimetype="text/event-stream")


@app.route("/api/ingest", methods=["POST", "OPTIONS"])
def ingest():
    if request.method == "OPTIONS":
        return ("", 204)

    if INGEST_TOKEN:
        bearer = request.headers.get("Authorization", "")
        custom = request.headers.get("X-Ingest-Token", "")
        good_bearer = bearer == f"Bearer {INGEST_TOKEN}"
        good_custom = custom == INGEST_TOKEN
        if not (good_bearer or good_custom):
            return jsonify({"status": "error", "reason": "unauthorized"}), 401

    data: dict[str, Any] = request.get_json(silent=True) or {}
    kind = str(data.get("kind", "telemetry"))

    if kind == "telemetry":
        satellite_id = str(data.get("satellite_id", ""))
        if not satellite_id:
            return jsonify({"status": "error", "reason": "missing_satellite_id"}), 400

        try:
            battery = float(data.get("battery", 0.0))
            temp_c = float(data.get("temp_c", 0.0))
        except (TypeError, ValueError):
            return jsonify({"status": "error", "reason": "invalid_numeric_fields"}), 400

        result = sim.ingest_external_telemetry(satellite_id=satellite_id, battery=battery, temp_c=temp_c)
        code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), code

    if kind == "command":
        satellite_id = str(data.get("satellite_id", ""))
        command = str(data.get("command", ""))
        if not satellite_id or not command:
            return jsonify({"status": "error", "reason": "missing_fields"}), 400

        delta_raw = data.get("delta", 0)
        try:
            delta = int(delta_raw)
        except (TypeError, ValueError):
            return jsonify({"status": "error", "reason": "invalid_delta"}), 400

        result = sim.ingest_external_command(command=command, satellite_id=satellite_id, delta=delta)
        code = 200 if result.get("status") == "ok" else 400
        return jsonify(result), code

    return jsonify({"status": "error", "reason": "unknown_kind"}), 400


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
