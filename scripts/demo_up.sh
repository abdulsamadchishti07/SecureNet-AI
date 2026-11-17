#!/usr/bin/env sh
# Start the local SecureNet AI demonstration stack (API + sensor).
# Defaults to safe dry-run offline PCAP replay on 127.0.0.1:8010.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

usage() {
    cat <<'EOF'
Usage: ./scripts/demo_up.sh [OPTIONS]

Options:
  --mode MODE             dry-run (default), live-dry-run, or enforced
  -r, --pcap PATH         PCAP file for offline replay (dry-run or enforced)
  -i, --iface IFACE       Live capture interface (live-dry-run or enforced)
  --protect CIDR          Protected IPv4/CIDR (repeatable; forwarded to sniffer)
  --helper-socket PATH    Helper Unix socket for enforced mode (default runtime/fw_helper.sock)
  --allow-unprotected-lab Explicit netns/lab bypass for --protect in enforced mode
  --linger-seconds N      Offline post-EOF linger seconds (default 300)
  -h, --help              Show this help
EOF
}

MODE="${DEMO_MODE:-dry-run}"
API_HOST="${API_HOST:-127.0.0.1}"
API_PORT="${API_PORT:-8010}"
SENSOR_CRED_FILE="${SENSOR_CRED_FILE:-runtime/sensor.env}"
PCAP_FILE="${PCAP_FILE:-}"
IFACE=""
HELPER_SOCKET="${HELPER_SOCKET:-runtime/fw_helper.sock}"
LINGER_SECONDS="${LINGER_SECONDS:-300}"
ALERT_LOG="${ALERT_LOG:-runtime/demo_alerts.jsonl}"
OUTBOX_PATH="${OUTBOX_PATH:-runtime/demo_alerts.outbox.sqlite3}"
ALLOW_UNPROTECTED_LAB=0
PROTECT_CIDRS=""
API_PID_FILE="runtime/demo_api.pid"
SENSOR_PID_FILE="runtime/demo_sensor.pid"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode)
            [ "$#" -ge 2 ] || { echo "Missing value for --mode" >&2; exit 2; }
            MODE="$2"; shift 2 ;;
        -r|--pcap)
            [ "$#" -ge 2 ] || { echo "Missing value for $1" >&2; exit 2; }
            PCAP_FILE="$2"; shift 2 ;;
        -i|--iface)
            [ "$#" -ge 2 ] || { echo "Missing value for $1" >&2; exit 2; }
            IFACE="$2"; shift 2 ;;
        --protect)
            [ "$#" -ge 2 ] || { echo "Missing value for --protect" >&2; exit 2; }
            case "$2" in
                *"$IFS"*|*"
"*) echo "Invalid --protect value: $2" >&2; exit 2 ;;
            esac
            PROTECT_CIDRS="${PROTECT_CIDRS:+${PROTECT_CIDRS} }${2}"
            shift 2 ;;
        --helper-socket)
            [ "$#" -ge 2 ] || { echo "Missing value for --helper-socket" >&2; exit 2; }
            HELPER_SOCKET="$2"; shift 2 ;;
        --allow-unprotected-lab)
            ALLOW_UNPROTECTED_LAB=1; shift ;;
        --linger-seconds)
            [ "$#" -ge 2 ] || { echo "Missing value for --linger-seconds" >&2; exit 2; }
            LINGER_SECONDS="$2"; shift 2 ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

case "$MODE" in
    dry-run|live-dry-run|enforced) ;;
    *) echo "Unsupported --mode: $MODE (expected dry-run, live-dry-run, or enforced)" >&2; exit 2 ;;
esac

if [ "$MODE" = "live-dry-run" ]; then
    [ -n "$IFACE" ] || { echo "--mode live-dry-run requires -i/--iface" >&2; exit 2; }
    [ -z "$PCAP_FILE" ] || { echo "--mode live-dry-run cannot be combined with -r/--pcap" >&2; exit 2; }
elif [ "$MODE" = "dry-run" ]; then
    [ -z "$IFACE" ] || { echo "--mode dry-run cannot be combined with -i/--iface (use --mode live-dry-run)" >&2; exit 2; }
    PCAP_FILE="${PCAP_FILE:-runtime/response_demo_offline.pcap}"
else
    if [ -n "$IFACE" ] && [ -n "$PCAP_FILE" ]; then
        echo "Specify either -i/--iface or -r/--pcap, not both" >&2
        exit 2
    fi
    if [ -z "$IFACE" ] && [ -z "$PCAP_FILE" ]; then
        PCAP_FILE="runtime/response_demo_offline.pcap"
    fi
    if [ -z "$PROTECT_CIDRS" ] && [ "$ALLOW_UNPROTECTED_LAB" -ne 1 ]; then
        echo "--mode enforced requires --protect <IPv4/CIDR> or --allow-unprotected-lab" >&2
        exit 2
    fi
    if [ ! -S "$HELPER_SOCKET" ]; then
        echo "Helper socket not found at $HELPER_SOCKET. Start backend/fw_helper.py first." >&2
        exit 2
    fi
fi

if [ "$API_PORT" = "8000" ] && [ "${ALLOW_PORT_8000:-0}" != "1" ]; then
    echo "Refusing port 8000 by default to preserve unrelated local services. Use API_PORT=8010." >&2
    exit 1
fi

[ -x ".venv/bin/python" ] || { echo "Missing .venv/bin/python. Create the virtual environment first." >&2; exit 1; }
[ -f "backend/.env" ] || { echo "Missing backend/.env. Run: .venv/bin/python -m backend.manage init-config" >&2; exit 1; }
[ -f "frontend/dist/index.html" ] || { echo "Missing frontend/dist/index.html. Run: npm --prefix frontend run build" >&2; exit 1; }
[ -f "$SENSOR_CRED_FILE" ] || { echo "Missing $SENSOR_CRED_FILE. Run: .venv/bin/python -m backend.manage export-sensor-env $SENSOR_CRED_FILE" >&2; exit 1; }

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

if [ -n "$PCAP_FILE" ] && [ ! -f "$PCAP_FILE" ]; then
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

STARTED_API_PID=""
cleanup_on_failure() {
    rm -f "$SENSOR_PID_FILE"
    if [ -n "$STARTED_API_PID" ] && kill -0 "$STARTED_API_PID" 2>/dev/null; then
        kill -TERM "$STARTED_API_PID" 2>/dev/null || true
        wait "$STARTED_API_PID" 2>/dev/null || true
    fi
    rm -f "$API_PID_FILE"
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
    STARTED_API_PID=$!
    echo "$STARTED_API_PID" >"$API_PID_FILE"

    attempt=0
    while ! api_healthy; do
        attempt=$((attempt + 1))
        if ! kill -0 "$STARTED_API_PID" 2>/dev/null || [ "$attempt" -ge 40 ]; then
            echo "Backend failed to become ready on http://${API_HOST}:${API_PORT}. Check runtime/demo_api.log." >&2
            cleanup_on_failure
            exit 1
        fi
        sleep 0.25
    done
    echo "Started SecureNet AI Backend (PID $STARTED_API_PID) at http://${API_HOST}:${API_PORT}"
fi

set -- --predict --respond --response-min-flows 3 \
    --api-url "http://${API_HOST}:${API_PORT}" \
    --alert-log "$ALERT_LOG" \
    --outbox "$OUTBOX_PATH"

if [ -n "$IFACE" ]; then
    set -- "$@" -i "$IFACE"
else
    set -- "$@" -r "$PCAP_FILE" --linger-seconds "$LINGER_SECONDS"
fi

if [ "$MODE" = "enforced" ]; then
    set -- "$@" --enforce --helper-socket "$HELPER_SOCKET"
    if [ "$ALLOW_UNPROTECTED_LAB" -eq 1 ]; then
        set -- "$@" --allow-unprotected-lab
    fi
fi

for cidr in $PROTECT_CIDRS; do
    set -- "$@" --protect "$cidr"
done

: >runtime/demo_sensor.log
: >runtime/demo_sensor_stdout.log

(
    set -a
    # shellcheck disable=SC1090
    case "$SENSOR_CRED_FILE" in
        */*) . "$SENSOR_CRED_FILE" ;;
        *) . "./$SENSOR_CRED_FILE" ;;
    esac
    set +a
    exec .venv/bin/python -m sniffer.main "$@" \
        >runtime/demo_sensor_stdout.log 2>runtime/demo_sensor.log
) &
sensor_pid=$!
echo "$sensor_pid" >"$SENSOR_PID_FILE"

# Wait for sensor readiness or catch immediate startup failures cleanly.
attempt=0
sensor_ready=0
while [ "$attempt" -lt 40 ]; do
    attempt=$((attempt + 1))
    if ! kill -0 "$sensor_pid" 2>/dev/null; then
        rc=0
        wait "$sensor_pid" || rc=$?
        if [ -z "$IFACE" ] && [ "$LINGER_SECONDS" = "0" ] && [ "$rc" -eq 0 ] \
                && grep -q "Response summary:" runtime/demo_sensor.log 2>/dev/null; then
            rm -f "$SENSOR_PID_FILE"
            echo "Completed offline sensor replay in $MODE mode (linger=0s)."
            echo "Dashboard: http://${API_HOST}:${API_PORT}"
            exit 0
        fi
        echo "Sensor failed during startup (exit $rc). Last log lines:" >&2
        tail -n 20 runtime/demo_sensor.log >&2 || true
        cleanup_on_failure
        exit 1
    fi
    if [ -n "$IFACE" ]; then
        # Live capture stays open waiting for packets; confirm it survives startup initialization.
        if [ "$attempt" -ge 8 ] && [ -e "${OUTBOX_PATH}.lock" ]; then
            sensor_ready=1
            break
        fi
    else
        if [ "$LINGER_SECONDS" != "0" ] \
                && grep -q "Replay complete; sensor stays available" runtime/demo_sensor.log 2>/dev/null; then
            sensor_ready=1
            break
        fi
    fi
    sleep 0.25
done

if [ "$sensor_ready" -ne 1 ]; then
    echo "Sensor did not become ready within 10s. Last log lines:" >&2
    tail -n 20 runtime/demo_sensor.log >&2 || true
    kill -TERM "$sensor_pid" 2>/dev/null || true
    wait "$sensor_pid" 2>/dev/null || true
    cleanup_on_failure
    exit 1
fi

echo "Started $MODE sensor (PID $sensor_pid)"
echo "Dashboard: http://${API_HOST}:${API_PORT}"
echo "Stop with: ./scripts/demo_down.sh"
