#!/usr/bin/env sh
# Start the local SecureNet AI dry-run demonstration stack (API + offline sensor replay).
# Never prints secrets or modifies host firewall rules.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8010}"
SENSOR_CRED_FILE="${SENSOR_CRED_FILE:-runtime/sensor.env}"
PCAP_FILE="${PCAP_FILE:-runtime/response_demo_offline.pcap}"
LINGER_SECONDS="${LINGER_SECONDS:-300}"
ALERT_LOG="${ALERT_LOG:-runtime/demo_alerts.jsonl}"
OUTBOX_PATH="${OUTBOX_PATH:-runtime/demo_alerts.outbox.sqlite3}"
API_PID_FILE="runtime/demo_api.pid"
SENSOR_PID_FILE="runtime/demo_sensor.pid"

if [ "$API_PORT" = "8000" ] && [ "${ALLOW_PORT_8000:-0}" != "1" ]; then
    echo "Refusing port 8000 by default to preserve unrelated local services. Use API_PORT=8010." >&2
    exit 1
fi

if [ ! -x ".venv/bin/python" ]; then
    echo "Missing .venv/bin/python. Create the virtual environment first." >&2
    exit 1
fi

if [ ! -f "backend/.env" ]; then
    echo "Missing backend/.env. Run: .venv/bin/python -m backend.manage init-config" >&2
    exit 1
fi

if [ ! -f "frontend/dist/index.html" ]; then
    echo "Missing frontend/dist/index.html. Run: npm --prefix frontend run build" >&2
    exit 1
fi

if [ ! -f "$SENSOR_CRED_FILE" ]; then
    echo "Missing $SENSOR_CRED_FILE. Run: .venv/bin/python -m backend.manage export-sensor-env $SENSOR_CRED_FILE" >&2
    exit 1
fi

mkdir -p runtime
chmod 600 "$SENSOR_CRED_FILE" 2>/dev/null || true

for pid_file in "$API_PID_FILE" "$SENSOR_PID_FILE"; do
    if [ -f "$pid_file" ]; then
        old_pid="$(cat "$pid_file" 2>/dev/null || true)"
        if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
            echo "Process $old_pid from $pid_file is already running. Run ./scripts/demo_down.sh first." >&2
            exit 1
        fi
        rm -f "$pid_file"
    fi
done

if [ ! -f "$PCAP_FILE" ]; then
    if [ "$PCAP_FILE" = "runtime/response_demo_offline.pcap" ]; then
        .venv/bin/python scripts/create_response_demo.py "$PCAP_FILE"
    else
        echo "PCAP file not found: $PCAP_FILE" >&2
        exit 1
    fi
fi

.venv/bin/python -m backend.manage migrate >/dev/null

api_healthy() {
    .venv/bin/python - "$API_HOST" "$API_PORT" <<'PY'
import json, sys, urllib.request
url = f"http://{sys.argv[1]}:{sys.argv[2]}/api/health"
try:
    with urllib.request.urlopen(url, timeout=1.5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        raise SystemExit(0 if data.get("service") == "SecureNet AI Backend" else 1)
except Exception:
    raise SystemExit(1)
PY
}

if api_healthy; then
    echo "Reusing running SecureNet AI Backend at http://${API_HOST}:${API_PORT}"
else
    .venv/bin/uvicorn backend.main:app \
        --host "$API_HOST" \
        --port "$API_PORT" \
        --no-access-log \
        --log-level warning \
        >runtime/demo_api.log 2>&1 &
    api_pid=$!
    echo "$api_pid" >"$API_PID_FILE"

    attempt=0
    while ! api_healthy; do
        attempt=$((attempt + 1))
        if ! kill -0 "$api_pid" 2>/dev/null || [ "$attempt" -ge 40 ]; then
            echo "Backend failed to become ready on http://${API_HOST}:${API_PORT}. Check runtime/demo_api.log." >&2
            rm -f "$API_PID_FILE"
            exit 1
        fi
        sleep 0.25
    done
    echo "Started SecureNet AI Backend (PID $api_pid) at http://${API_HOST}:${API_PORT}"
fi

(
    set -a
    # shellcheck disable=SC1090
    . "./$SENSOR_CRED_FILE"
    set +a
    exec .venv/bin/python -m sniffer.main \
        -r "$PCAP_FILE" \
        --predict \
        --respond \
        --response-min-flows 3 \
        --api-url "http://${API_HOST}:${API_PORT}" \
        --alert-log "$ALERT_LOG" \
        --outbox "$OUTBOX_PATH" \
        --linger-seconds "$LINGER_SECONDS" \
        >runtime/demo_sensor_stdout.log 2>runtime/demo_sensor.log
) &
sensor_pid=$!
echo "$sensor_pid" >"$SENSOR_PID_FILE"

echo "Started dry-run sensor replay (PID $sensor_pid, linger=${LINGER_SECONDS}s)"
echo "Dashboard: http://${API_HOST}:${API_PORT}"
echo "Stop with: ./scripts/demo_down.sh"

