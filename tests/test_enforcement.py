"""Privilege-separated nftables helper, enforced lifecycle and reconciliation tests."""

import json
from threading import Event
from uuid import uuid4

import pytest

from backend.firewall import FirewallController
from backend.fw_client import EnforcementError, FwHelperClient, nft_block_command, nft_rollback_command, nft_unblock_command
from backend.fw_helper import FwHelperServer
from backend.models import ResponseCommand
from backend.worker import ResponseDispatcher
from sniffer.main import main as sniffer_main
from sniffer.rules import ResponsePolicy
from tests.test_delivery import ClientTransport


class StubNftRunner:
    def __init__(self):
        self.calls = []
        self.fail_next = None

    def __call__(self, args, stdin_text=None):
        self.calls.append((list(args), stdin_text))
        if self.fail_next is not None:
            err = self.fail_next
            self.fail_next = None
            return 1, err
        return 0, ""


def test_helper_unix_socket_lifecycle_idempotency_and_lease_watchdog(tmp_path, manual_clock):
    sock_path = tmp_path / "fw_helper.sock"
    runner = StubNftRunner()
    with FwHelperServer(
        socket_path=sock_path,
        protected=["10.0.0.1/32"],
        max_blocks=2,
        lease_seconds=10.0,
        runner=runner,
        clock=manual_clock,
    ) as server:
        client = FwHelperClient(sock_path)
        hello = client.start()
        assert hello["ok"] and hello["max_blocks"] == 2
        assert "10.0.0.1/32" in hello["protected_cidrs"]
        assert runner.calls[-1][0] == ["nft", "-f", "-"]
        assert "table ip securenet" in runner.calls[-1][1]

        # Independent helper-enforced protected CIDR check
        protected_reply = client.block("10.0.0.1", 60, block_id=str(uuid4()))
        assert protected_reply["status"] == "protected"

        # Idempotent op_id does not re-execute nft
        block_id_1 = str(uuid4())
        op_id = str(uuid4())
        first = client.block("10.10.0.9", 60, block_id=block_id_1, op_id=op_id)
        calls_after_first = len(runner.calls)
        duplicate_op = client.block("10.10.0.9", 60, block_id=block_id_1, op_id=op_id)
        assert first == duplicate_op
        assert first["status"] == "blocked"
        assert first["command"] == nft_block_command("10.10.0.9", 60)
        assert len(runner.calls) == calls_after_first

        # Duplicate IP returns already_blocked
        already = client.block("10.10.0.9", 60, block_id=str(uuid4()))
        assert already["status"] == "already_blocked"
        assert already["block_id"] == block_id_1

        # Second IP reaches capacity=2; third IP returns capacity_reached
        block_id_2 = str(uuid4())
        assert client.block("10.10.0.10", 60, block_id=block_id_2)["status"] == "blocked"
        assert client.block("10.10.0.11", 60, block_id=str(uuid4()))["status"] == "capacity_reached"

        # Stale block_id does not remove active block
        stale = client.unblock("10.10.0.9", block_id=str(uuid4()))
        assert stale["status"] == "stale_block"

        # Matching unblock removes element
        unblocked = client.unblock("10.10.0.9", block_id=block_id_1)
        assert unblocked["status"] == "unblocked"
        assert unblocked["command"] == nft_unblock_command("10.10.0.9")
        assert client.unblock("10.10.0.9", block_id=block_id_1)["status"] == "already_unblocked"

        # Lease expiration triggers automatic table rollback
        manual_clock.advance(11.0)
        rolled_back = server.check_lease()
        assert rolled_back == [block_id_2]
        assert runner.calls[-1][0] == nft_rollback_command()
        status = client.status()
        assert not status["table_active"] and not status["lease_active"]
        assert status["rolled_back_block_ids"] == [block_id_2]


def test_helper_rejects_unauthorized_peer_uid(tmp_path):
    sock_path = tmp_path / "unauth.sock"
    runner = StubNftRunner()
    with FwHelperServer(socket_path=sock_path, allowed_uids={999_999}, runner=runner):
        client = FwHelperClient(sock_path)
        with pytest.raises(EnforcementError, match="unauthorized_peer_uid"):
            client.start()
    assert runner.calls == []


def test_enforced_controller_guardrails_and_expiry(tmp_path, manual_clock):
    with pytest.raises(ValueError, match="helper_client"):
        FirewallController(mode="enforced", protected=["10.0.0.1/32"])
    with pytest.raises(ValueError, match="protected CIDR"):
        FirewallController(mode="enforced", helper_client=FwHelperClient(tmp_path / "s.sock"))

    sock_path = tmp_path / "ctrl.sock"
    runner = StubNftRunner()
    with FwHelperServer(socket_path=sock_path, runner=runner, clock=manual_clock):
        client = FwHelperClient(sock_path)
        firewall = FirewallController(
            protected=["10.0.0.1/32"],
            duration_seconds=15,
            mode="enforced",
            helper_client=client,
            clock=manual_clock,
        )
        assert firewall.max_blocks == 256
        firewall.start()
        blocked = firewall.block_ip("10.10.0.9", "PORTSCAN")
        assert blocked["status"] == "blocked"
        assert blocked["mode"] == "enforced"
        assert blocked["command"] == nft_block_command("10.10.0.9", 15)
        assert firewall.block_ip("10.10.0.9", "DOS")["status"] == "already_blocked"
        manual_clock.advance(10)
        assert firewall.heartbeat()["active_blocks"] == 1
        manual_clock.advance(5)
        (expired,) = firewall.expire()
        assert expired["status"] == "unblocked"
        assert expired["reason"] == "expired"
        assert expired["command"] == nft_unblock_command("10.10.0.9")


def test_enforced_dispatcher_api_round_trip_and_shutdown_rollback_reconciliation(
        backend_runtime, sensor_headers, admin_headers, response_event_factory, tmp_path):
    client = backend_runtime.client
    sock_path = tmp_path / "roundtrip.sock"
    runner = StubNftRunner()

    class EnforcedTransport(ClientTransport):
        def __init__(self, app_client, headers):
            super().__init__(app_client, headers)
            self.reconciled = Event()

        def request(self, path, payload=None):
            res = super().request(path, payload)
            if path == "/api/sensor/reconcile":
                self.reconciled.set()
            return res

    transport = EnforcedTransport(client, sensor_headers)
    with FwHelperServer(socket_path=sock_path, runner=runner):
        fw = FirewallController(
            protected=["10.0.0.1/32"],
            duration_seconds=300,
            mode="enforced",
            helper_client=FwHelperClient(sock_path),
        )
        with ResponseDispatcher(
            tmp_path / "enforced.jsonl",
            policy=ResponsePolicy(min_flows=1),
            firewall=fw,
            api_url="http://127.0.0.1:8000",
            transport=transport,
        ) as worker:
            # 1. First IP is blocked and manually unblocked via API + sensor ack
            ev1 = response_event_factory(src_ip="10.10.0.9")
            worker.publish(ev1)
            assert transport.ingested.wait(timeout=5)
            stats = client.get("/api/stats", headers=admin_headers).json()
            assert stats["active_blocked_ips"] == 1
            assert stats["active_simulated_blocks"] == 0
            assert stats["response_mode"] == "enforced"

            unblock_resp = client.post("/api/firewall/unblock/10.10.0.9", headers=admin_headers)
            assert unblock_resp.status_code == 202
            assert unblock_resp.json()["mode"] == "enforced"
            assert transport.acked.wait(timeout=5)
            unblocked_rows = client.get("/api/firewall/blocked?status=UNBLOCKED", headers=admin_headers).json()
            assert len(unblocked_rows) == 1 and unblocked_rows[0]["mode"] == "enforced"

            # 2. Second IP is blocked and has a pending unblock command when sensor shuts down
            transport.ingested.clear()
            ev2 = response_event_factory(src_ip="10.10.0.10")
            worker.publish(ev2)
            assert transport.ingested.wait(timeout=5)

    # Exiting the ResponseDispatcher context rolls back the helper table and reconciles DB rows
    rolled_back = client.get("/api/firewall/blocked?status=ROLLED_BACK", headers=admin_headers).json()
    assert len(rolled_back) == 1
    assert rolled_back[0]["ip"] == "10.10.0.10"
    assert rolled_back[0]["mode"] == "enforced"
    stats_after = client.get("/api/stats", headers=admin_headers).json()
    assert stats_after["active_blocked_ips"] == 0
    assert stats_after["response_mode"] == "dry_run"


def test_reconcile_cancels_pending_unblock_commands(
        backend_runtime, sensor_headers, admin_headers, response_event_factory):
    from datetime import datetime, timedelta, timezone
    client = backend_runtime.client
    event = response_event_factory(src_ip="10.10.0.25").to_dict()
    block_id = str(uuid4())
    now = datetime.now(timezone.utc)
    body = {
        "event": event,
        "decision": {"action": "candidate", "reason": "repeated_high_score_flows", "evidence_count": 3},
        "firewall": {
            "mode": "enforced",
            "ip": "10.10.0.25",
            "threat": "PORTSCAN",
            "status": "blocked",
            "block": {
                "block_id": block_id,
                "ip": "10.10.0.25",
                "threat": "PORTSCAN",
                "mode": "enforced",
                "blocked_at": now.isoformat(),
                "unblock_at": (now + timedelta(minutes=15)).isoformat(),
            },
            "command": nft_block_command("10.10.0.25", 900),
        },
    }
    assert client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 201
    unblock = client.post(f"/api/firewall/unblock/10.10.0.25?block_id={block_id}", headers=admin_headers)
    assert unblock.status_code == 202
    command_id = unblock.json()["command_id"]
    assert client.get("/api/stats", headers=admin_headers).json()["pending_unblocks"] == 1

    reconcile = client.post(
        "/api/sensor/reconcile",
        json={"mode": "enforced", "active_block_ids": [], "reason": "lease_loss_rollback"},
        headers=sensor_headers,
    )
    assert reconcile.status_code == 200 and reconcile.json()["rolled_back"] == 1
    assert client.get("/api/stats", headers=admin_headers).json()["pending_unblocks"] == 0
    rolled = client.get("/api/firewall/blocked?status=ROLLED_BACK", headers=admin_headers).json()
    assert len(rolled) == 1 and rolled[0]["block_id"] == block_id
    with backend_runtime.app.state.session_factory() as db:
        cmd = db.get(ResponseCommand, command_id)
        assert cmd.status == "CANCELLED"
        assert cmd.result == {"reason": "lease_loss_rollback"}


def test_helper_failure_stops_worker_loudly_and_records_lease_loss_reconcile(
        response_event_factory, tmp_path):
    sock_path = tmp_path / "fail.sock"
    runner = StubNftRunner()
    with FwHelperServer(socket_path=sock_path, runner=runner):
        runner.fail_next = None
        fw = FirewallController(
            protected=["10.0.0.1/32"],
            mode="enforced",
            helper_client=FwHelperClient(sock_path),
        )
        worker = ResponseDispatcher(
            tmp_path / "fail.jsonl",
            policy=ResponsePolicy(min_flows=1),
            firewall=fw,
        )
        with pytest.raises(RuntimeError, match="worker failed") as caught:
            with worker:
                runner.fail_next = "simulated kernel error"
                worker.publish(response_event_factory(src_ip="10.10.0.99"))
                deadline = __import__("time").monotonic() + 2.0
                while not worker.stats()["worker_failed"] and __import__("time").monotonic() < deadline:
                    __import__("time").sleep(0.05)
        assert isinstance(caught.value.__cause__, EnforcementError)
    records = [json.loads(line) for line in (tmp_path / "fail.jsonl").read_text().splitlines()]
    assert records[-1]["record_type"] == "reconcile"
    assert records[-1]["reason"] == "lease_loss_rollback"


@pytest.mark.parametrize("argv,expected", [
    (["-r", "in.pcap", "--predict", "--enforce"], "--enforce requires --respond"),
    (["-r", "in.pcap", "--predict", "--respond", "--enforce", "--clock-mode", "event_time", "--protect", "10.0.0.1/32"],
     "--enforce cannot be combined with --clock-mode event_time"),
    (["-r", "in.pcap", "--predict", "--respond", "--enforce"],
     "--enforce requires at least one --protect <IPv4/CIDR> or --allow-unprotected-lab"),
    (["-r", "in.pcap", "--predict", "--respond", "--allow-unprotected-lab"],
     "--allow-unprotected-lab requires --enforce"),
])
def test_sniffer_cli_rejects_unsafe_enforcement_flags(argv, expected, capsys):
    with pytest.raises(SystemExit) as caught:
        sniffer_main(argv)
    assert caught.value.code == 2
    assert expected in capsys.readouterr().err
