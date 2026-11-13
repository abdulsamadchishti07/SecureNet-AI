#!/usr/bin/env sh
# Gracefully stop the local SecureNet AI demonstration processes and verify outbox drain.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

API_PID_FILE="runtime/demo_api.pid"
SENSOR_PID_FILE="runtime/demo_sensor.pid"
OUTBOX_PATH="${OUTBOX_PATH:-runtime/demo_alerts.outbox.sqlite3}"

stop_pid_file() {
    label="$1"
    file="$2"
    if [ ! -f "$file" ]; then
        return 0
    fi
    pid="$(cat "$file" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        waited=0
        while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 40 ]; do
            sleep 0.25
            waited=$((waited + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            echo "Warning: $label (PID $pid) did not exit after 10s; sending SIGKILL." >&2
            kill -KILL "$pid" 2>/dev/null || true
        else
            echo "Stopped $label (PID $pid)."
        fi
    fi
    rm -f "$file"
}

stop_pid_file "sensor" "$SENSOR_PID_FILE"

if [ -f "$OUTBOX_PATH" ] && [ -x ".venv/bin/python" ]; then
    echo "Outbox status ($OUTBOX_PATH): $(.venv/bin/python -m backend.outbox status "$OUTBOX_PATH")"
fi

stop_pid_file "backend API" "$API_PID_FILE"

