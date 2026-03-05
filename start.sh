#!/usr/bin/env sh
set -e

ROLE="${SERVICE_ROLE:-api}"
PORT="${PORT:-8080}"

if [ "$ROLE" = "worker" ]; then
  exec python worker.py
fi

exec gunicorn --bind "0.0.0.0:${PORT}" --workers 1 --threads 4 app:app
