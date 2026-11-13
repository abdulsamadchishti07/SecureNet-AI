#!/usr/bin/env sh
# Isolated Linux network-namespace verification of the privileged nftables helper
# and unprivileged ResponseDispatcher in enforced mode.
# Never modifies the host's default network namespace firewall tables.

set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -x ".venv/bin/python" ]; then
    echo "Missing .venv/bin/python." >&2
    exit 1
fi

if ! command -v nft >/dev/null 2>&1; then
    echo "Missing nft binary (/usr/sbin/nft or /usr/bin/nft)." >&2
    exit 1
fi

if [ "${SECURENET_IN_NETNS:-0}" != "1" ]; then
    HOST_UID="$(id -u)"
    export SECURENET_IN_NETNS=1
    export SECURENET_HOST_UID="$HOST_UID"
    if [ "$HOST_UID" -eq 0 ]; then
        exec unshare --net "$0" "$@"
    elif unshare -r --net ip link show lo >/dev/null 2>&1; then
        exec unshare -r --net "$0" "$@"
    else
        echo "Entering isolated network namespace via sudo unshare --net (host firewall remains untouched)..."
        exec sudo SECURENET_IN_NETNS=1 SECURENET_HOST_UID="$HOST_UID" unshare --net "$0" "$@"
    fi
fi

ip link set lo up
ip link add veth-sensor type veth peer name veth-attk
ip addr add 10.200.0.1/24 dev veth-sensor
ip addr add 10.200.0.2/24 dev veth-attk
ip link set veth-sensor up
ip link set veth-attk up

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/securenet-netns.XXXXXX")"
HELPER_PID=""
cleanup() {
    if [ -n "$HELPER_PID" ] && kill -0 "$HELPER_PID" 2>/dev/null; then
        kill -TERM "$HELPER_PID" 2>/dev/null || true
        wait "$HELPER_PID" 2>/dev/null || true
    fi
    nft delete table ip securenet >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

ALLOWED_UID="${SECURENET_HOST_UID:-$(id -u)}"
/usr/bin/python3 -I "$ROOT/backend/fw_helper.py" \
    --socket "$WORK_DIR/fw_helper.sock" \
    --protect 10.200.0.1/32 \
    --max-blocks 16 \
    --lease-seconds 10 \
    --allowed-uid "$ALLOWED_UID" \
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

.venv/bin/python - "$WORK_DIR" <<'PY'
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from backend.firewall import FirewallController
from backend.fw_client import FwHelperClient
from backend.worker import ResponseDispatcher
from ml_engine.datasets import FEATURE_COLUMNS
from sniffer.events import DetectionEvent
from sniffer.rules import ResponsePolicy

work_dir = Path(sys.argv[1])
sock_path = work_dir / "fw_helper.sock"
log_path = work_dir / "enforced_alerts.jsonl"

features = {name: 0.0 for name in FEATURE_COLUMNS}
features.update({"Src Port": 44444, "Dst Port": 80, "Protocol": 6, "Flow Duration": 1000.0})
probs = {
    "BENIGN": 0.001, "BOTNET": 0.001, "BRUTE_FORCE": 0.001,
    "DDOS": 0.001, "DOS": 0.001, "PORTSCAN": 0.994, "WEB_ATTACK": 0.001,
}

def make_event(src_ip="10.200.0.2"):
    return DetectionEvent(
        src_ip=src_ip, dst_ip="10.200.0.1", features=features,
        label="PORTSCAN", confidence=0.994, probabilities=probs,
        model_scope="unified", model_sha256="a" * 64, source="live",
        event_id=str(uuid4()), observed_at=datetime.now(timezone.utc),
    )

client = FwHelperClient(sock_path)
firewall = FirewallController(
    protected=["10.200.0.1/32"], duration_seconds=60, max_blocks=16,
    mode="enforced", helper_client=client,
)
policy = ResponsePolicy(confidence=0.90, min_flows=2, window_seconds=60)

with ResponseDispatcher(log_path, policy=policy, firewall=firewall) as worker:
    assert worker.publish(make_event())
    assert worker.publish(make_event())
    import time
    deadline = time.monotonic() + 5.0
    while worker.stats()["enforced_blocks"] < 1 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert worker.stats()["enforced_blocks"] == 1
    ruleset = subprocess.run(["nft", "list", "table", "ip", "securenet"], capture_output=True, text=True, check=True).stdout
    assert "10.200.0.2" in ruleset and "timeout" in ruleset

after = subprocess.run(["nft", "list", "table", "ip", "securenet"], capture_output=True, text=True)
assert after.returncode != 0, "Expected table ip securenet to be deleted on dispatcher shutdown rollback"
records = [json.loads(line) for line in log_path.read_text().splitlines()]
assert records[0]["record_type"] == "reconcile" and records[0]["reason"] == "startup_rollback"
assert records[-1]["record_type"] == "reconcile" and records[-1]["reason"] == "shutdown_rollback"
print(json.dumps({
    "status": "ok",
    "enforced_blocks": worker.stats()["enforced_blocks"],
    "table_removed_on_close": after.returncode != 0,
    "audit_records": len(records),
}))
PY
