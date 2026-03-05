from __future__ import annotations

from flask import Flask, jsonify, render_template

from cosmic_sea.simulator import CosmicSeaSimulator


sim = CosmicSeaSimulator(num_satellites=6, tick_interval=1.0)
sim.start()

app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/state")
def state():
    return jsonify(sim.snapshot())


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
