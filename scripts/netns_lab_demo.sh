#!/usr/bin/env sh
# Dual-namespace isolated Linux lab verification of real nftables packet drops,
# manual unblock recovery, and SIGKILL worker-crash lease rollback + DB reconciliation.
# Never modifies the host network or the configured PostgreSQL database.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

for tool in nft ip ping nsenter unshare; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required Linux networking utility: $tool" >&2
        exit 1
    fi
done
if [ ! -x ".venv/bin/python" ]; then
    echo "Missing .venv/bin/python." >&2
    exit 1
fi

if [ "${SECURENET_IN_NETNS:-0}" != "1" ]; then
    export SECURENET_IN_NETNS=1
    unset SUDO_UID SUDO_GID 2>/dev/null || true
    if [ "$(id -u)" -eq 0 ]; then
        exec unshare --net "$0" "$@"
    elif unshare -r --net ip link show lo >/dev/null 2>&1; then
        exec unshare -r --net "$0" "$@"
    else
        echo "Entering isolated network namespace via sudo unshare --net (host firewall untouched)..."
        exec sudo SECURENET_IN_NETNS=1 unshare --net "$0" "$@"
    fi
fi

mkdir -p "$ROOT/runtime"
WORK_DIR="$(mktemp -d "$ROOT/runtime/securenet-netns.XXXXXX")"
ATTK_PID=""
HELPER_PID=""
API_PID=""
SENSOR_PID=""

cleanup() {
    for pid in "$SENSOR_PID" "$API_PID" "$HELPER_PID" "$ATTK_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    nft delete table ip securenet >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# Create peer attacker namespace inside a separate network namespace connected via veth.
unshare --net sh -c 'exec sleep 120' &
ATTK_PID=$!
sleep 0.2

ip link set lo up
ip link add veth-sensor type veth peer name veth-attk
ip addr add 10.200.0.1/24 dev veth-sensor
ip link set veth-sensor up
ip link set veth-attk netns "$ATTK_PID"

nsenter --net=/proc/"$ATTK_PID"/ns/net sh -c '
    ip link set lo up
    ip link set veth-attk up
    ip addr add 10.200.0.2/24 dev veth-attk
'

# 1. Start privilege-separated nftables helper with short 5s lease watchdog.
/usr/bin/python3 -I "$ROOT/backend/fw_helper.py" \
    --socket "$WORK_DIR/fw_helper.sock" \
    --protect 10.200.0.1/32 \
    --max-blocks 16 \
    --lease-seconds 5 \
    --allowed-uid "$(id -u)" \
    >"$WORK_DIR/helper.log" 2>&1 &
HELPER_PID=$!

waited=0
while [ ! -S "$WORK_DIR/fw_helper.sock" ]; do
    waited=$((waited + 1))
    if ! kill -0 "$HELPER_PID" 2>/dev/null || [ "$waited" -ge 40 ]; then
        echo "Helper failed to start inside netns:" >&2
        cat "$WORK_DIR/helper.log" >&2 || true
        exit 1
    fi
    sleep 0.1
done

# 2. Start isolated backend API (private SQLite DB in WORK_DIR; never touches backend/.env DB).
API_PORT=18010
JWT_SECRET="netns-ephemeral-jwt-secret-min-32bytes-0000"
SENSOR_TOKEN="netns-ephemeral-sensor-secret-min-32bytes"
SENSOR_ID="sensor-netns"
DB_URL="sqlite:///$WORK_DIR/lab.sqlite3"

env -i PATH="$PATH" HOME="$HOME" TMPDIR="$WORK_DIR" \
    DATABASE_URL="$DB_URL" \
    SECRET_KEY="$JWT_SECRET" \
    SENSOR_API_TOKEN="$SENSOR_TOKEN" \
    SENSOR_ID="$SENSOR_ID" \
    CORS_ORIGINS="http://127.0.0.1:$API_PORT" \
    .venv/bin/python - <<'PY'
import os
from backend.auth import hash_password
from backend.database import create_database_engine, init_db, sessions_for
from backend.models import User

engine = create_database_engine(os.environ["DATABASE_URL"])
init_db(engine)
with sessions_for(engine)() as db:
    db.add(User(
        username="netns_admin",
        email="netns-admin@example.com",
        hashed_password=hash_password("NetnsAdminPass123!"),
        is_admin=True,
    ))
    db.commit()
engine.dispose()
PY

env -i PATH="$PATH" HOME="$HOME" TMPDIR="$WORK_DIR" \
    DATABASE_URL="$DB_URL" \
    SECRET_KEY="$JWT_SECRET" \
    SENSOR_API_TOKEN="$SENSOR_TOKEN" \
    SENSOR_ID="$SENSOR_ID" \
    CORS_ORIGINS="http://127.0.0.1:$API_PORT" \
    .venv/bin/uvicorn backend.main:app \
        --host 127.0.0.1 \
        --port "$API_PORT" \
        --no-access-log \
        --log-level warning \
        >"$WORK_DIR/api.log" 2>&1 &
API_PID=$!

# 3. Start real live capture sniffer in enforced mode on veth-sensor.
env -i PATH="$PATH" HOME="$HOME" TMPDIR="$WORK_DIR" \
    SENSOR_API_TOKEN="$SENSOR_TOKEN" \
    SENSOR_ID="$SENSOR_ID" \
    .venv/bin/python -m sniffer.main \
        -i veth-sensor \
        -f "tcp portrange 8081-8083" \
        --termination-grace 0.1 \
        --predict \
        --respond \
        --enforce \
        --helper-socket "$WORK_DIR/fw_helper.sock" \
        --protect 10.200.0.1/32 \
        --response-min-flows 3 \
        --block-seconds 60 \
        --alert-log "$WORK_DIR/alerts.jsonl" \
        --outbox "$WORK_DIR/outbox.sqlite3" \
        --api-url "http://127.0.0.1:$API_PORT" \
        --sensor-id "$SENSOR_ID" \
        >"$WORK_DIR/sensor_stdout.log" 2>"$WORK_DIR/sensor.log" &
SENSOR_PID=$!

# 4. Run end-to-end traffic, drop, manual-unblock, and crash-recovery orchestrator in Python.
.venv/bin/python - "$WORK_DIR" "$API_PORT" "$ATTK_PID" "$SENSOR_PID" "$SENSOR_TOKEN" "$SENSOR_ID" <<'PY'
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request

work_dir = Path(sys.argv[1])
api_port = int(sys.argv[2])
attk_pid = int(sys.argv[3])
sensor_pid = int(sys.argv[4])
sensor_token = sys.argv[5]
sensor_id = sys.argv[6]
api_base = f"http://127.0.0.1:{api_port}"

# Real protected TCP target in sensor namespace on 10.200.0.1:18080
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind(("10.200.0.1", 18080))
server_sock.listen(16)
stop_server = threading.Event()

def serve_echo():
    server_sock.settimeout(0.2)
    while not stop_server.is_set():
        try:
            conn, _ = server_sock.accept()
        except TimeoutError:
            continue
        except OSError:
            break
        with conn:
            conn.sendall(b"OK\n")

server_thread = threading.Thread(target=serve_echo, daemon=True)
server_thread.start()

def api_req(path, method="GET", form=None, token=None):
    headers = {}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        body = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(api_base + path, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=3) as resp:
        return json.loads(resp.read().decode("utf-8"))

def attk_py(code):
    return subprocess.run(
        ["nsenter", f"--net=/proc/{attk_pid}/ns/net", ".venv/bin/python", "-c", code],
        capture_output=True, text=True, check=False,
    )

def attk_tcp_reachable():
    return attk_py(
        "import socket\ns=socket.socket()\ns.settimeout(0.6)\ntry:\n"
        " s.connect(('10.200.0.1', 18080))\n assert s.recv(8) == b'OK\\n'\nfinally:\n s.close()"
    ).returncode == 0

def attk_ping_reachable():
    res = subprocess.run(
        ["nsenter", f"--net=/proc/{attk_pid}/ns/net", "ping", "-c1", "-W1", "10.200.0.1"],
        capture_output=True, text=True, check=False,
    )
    return res.returncode == 0

def send_scan_burst():
    res = attk_py(
        "import socket\nfor p in (8081, 8082, 8083):\n s=socket.socket()\n"
        " try: s.connect(('10.200.0.1', p))\n except OSError: pass\n finally: s.close()"
    )
    if res.returncode != 0:
        raise RuntimeError(f"send_scan_burst failed: {res.stderr}")

def wait_for_blocks(target, token):
    deadline = time.monotonic() + 10.0
    stats = None
    while time.monotonic() < deadline:
        stats = api_req("/api/stats", token=token)
        if stats["active_blocked_ips"] == target:
            return stats
        time.sleep(0.2)
    return stats

try:
    # Wait for API health & sensor startup outbox lock.
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        try:
            if api_req("/api/health").get("status") == "ok" and (work_dir / "outbox.sqlite3.lock").exists():
                break
        except Exception:
            pass
        time.sleep(0.2)
    else:
        raise RuntimeError("Isolated API or live sensor did not become ready in time")

    # Wait briefly for AsyncSniffer thread inside sniffer.main to open AF_PACKET socket.
    time.sleep(0.8)
    admin_token = api_req("/api/auth/login", method="POST",
                          form={"username": "netns_admin", "password": "NetnsAdminPass123!"})["access_token"]

    # Step 1: Baseline reachability from attacker netns -> sensor netns
    assert attk_tcp_reachable(), "Baseline TCP connect from attacker netns failed"
    assert attk_ping_reachable(), "Baseline ICMP ping from attacker netns failed"

    # Step 2: Trigger real live PORTSCAN classification -> enforced nftables block
    send_scan_burst()
    stats = wait_for_blocks(1, admin_token)
    assert stats["active_blocked_ips"] == 1 and stats["response_mode"] == "enforced", f"Expected enforced block, got {stats}"

    # Step 3: Prove real kernel packet drops (TCP + ICMP blocked by nftables hook input)
    assert not attk_tcp_reachable(), "TCP traffic was NOT dropped by nftables!"
    assert not attk_ping_reachable(), "ICMP traffic was NOT dropped by nftables!"

    # Step 4: Prove manual admin unblock recovery via API -> sensor ack -> connectivity restored
    api_req("/api/firewall/unblock/10.200.0.2", method="POST", token=admin_token)
    stats = wait_for_blocks(0, admin_token)
    assert stats["active_blocked_ips"] == 0, f"Manual unblock failed to clear block: {stats}"
    assert attk_tcp_reachable(), "TCP traffic did not recover after manual unblock!"
    assert attk_ping_reachable(), "ICMP traffic did not recover after manual unblock!"

    # Step 5: Trigger a second live block, then SIGKILL sensor to prove helper lease watchdog recovery
    send_scan_burst()
    stats = wait_for_blocks(1, admin_token)
    assert stats["active_blocked_ips"] == 1, f"Expected second block, got {stats}"
    assert not attk_tcp_reachable(), "Second block did not drop TCP traffic"

    os.kill(sensor_pid, signal.SIGKILL)
    dead_deadline = time.monotonic() + 5.0
    while time.monotonic() < dead_deadline:
        try:
            stat_text = Path(f"/proc/{sensor_pid}/stat").read_text()
            proc_state = stat_text.rsplit(")", 1)[-1].strip().split()[0]
            if proc_state in ("Z", "X"):
                break
        except FileNotFoundError:
            break
        time.sleep(0.05)

    # Wait for 5s helper lease watchdog to expire and flush table ip securenet
    deadline = time.monotonic() + 9.0
    while time.monotonic() < deadline:
        res = subprocess.run(["nft", "list", "table", "ip", "securenet"], capture_output=True, text=True)
        if res.returncode != 0:
            break
        time.sleep(0.25)
    assert subprocess.run(["nft", "list", "table", "ip", "securenet"], capture_output=True).returncode != 0, \
        "Helper watchdog did not delete table ip securenet after worker SIGKILL"
    assert attk_tcp_reachable(), "TCP traffic did not recover after worker crash lease rollback!"

    # Step 6: Restart sensor briefly & send SIGTERM to prove startup DB reconciliation + clean SIGTERM exit
    reconciler = subprocess.Popen([
        ".venv/bin/python", "-m", "sniffer.main",
        "-i", "veth-sensor",
        "-f", "tcp port 65432",
        "--predict", "--respond", "--enforce",
        "--helper-socket", str(work_dir / "fw_helper.sock"),
        "--protect", "10.200.0.1/32",
        "--alert-log", str(work_dir / "alerts.jsonl"),
        "--outbox", str(work_dir / "outbox.sqlite3"),
        "--api-url", api_base,
        "--sensor-id", sensor_id,
    ], env={**os.environ, "SENSOR_API_TOKEN": sensor_token, "SENSOR_ID": sensor_id},
       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        rolled = api_req("/api/firewall/blocked?status=ROLLED_BACK", token=admin_token)
        if rolled:
            break
        time.sleep(0.2)
    reconciler.send_signal(signal.SIGTERM)
    _, rec_err = reconciler.communicate(timeout=10)
    assert reconciler.returncode == 0, f"Expected clean SIGTERM exit 0, got {reconciler.returncode}: {rec_err}"
    assert "Response summary:" in rec_err
    assert len(api_req("/api/firewall/blocked?status=ROLLED_BACK", token=admin_token)) == 1
    assert len(api_req("/api/firewall/blocked?status=UNBLOCKED", token=admin_token)) == 1

    print(json.dumps({
        "status": "ok",
        "baseline_reachable": True,
        "packet_drop_verified": True,
        "manual_unblock_recovered": True,
        "sigkill_lease_rollback_recovered": True,
        "sigterm_exit_code": reconciler.returncode,
        "db_rolled_back": 1,
        "db_unblocked": 1,
    }))
finally:
    stop_server.set()
    server_sock.close()
PY
