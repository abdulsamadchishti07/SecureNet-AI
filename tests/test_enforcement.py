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


def test_duplicate_worker_locked_outbox_and_active_lease_protection(
        backend_runtime, sensor_headers, response_event_factory, tmp_path, manual_clock):
    sock_path = tmp_path / "dup.sock"
    runner = StubNftRunner()
    transport = ClientTransport(backend_runtime.client, sensor_headers)
    shared_outbox = tmp_path / "shared.sqlite3"
    with FwHelperServer(socket_path=sock_path, protected=["10.0.0.1/32"], runner=runner, clock=manual_clock) as srv:
        fw1 = FirewallController(
            protected=["10.0.0.1/32"],
            mode="enforced",
            helper_client=FwHelperClient(sock_path),
            clock=manual_clock,
        )
        with ResponseDispatcher(
            tmp_path / "dup1.jsonl",
            policy=ResponsePolicy(min_flows=1),
            firewall=fw1,
            api_url="http://127.0.0.1:8000",
            transport=transport,
            outbox_path=shared_outbox,
        ) as worker1:
            worker1.publish(response_event_factory(src_ip="10.10.0.9"))
            assert transport.ingested.wait(timeout=5)
            orig_lease = fw1.helper_client.lease_id
            assert srv._lease_id == orig_lease
            calls_before = len(runner.calls)

            fw2 = FirewallController(
                protected=["10.0.0.1/32"],
                mode="enforced",
                helper_client=FwHelperClient(sock_path),
                clock=manual_clock,
            )
            worker2 = ResponseDispatcher(
                tmp_path / "dup2.jsonl",
                policy=ResponsePolicy(min_flows=1),
                firewall=fw2,
                api_url="http://127.0.0.1:8000",
                transport=ClientTransport(backend_runtime.client, sensor_headers),
                outbox_path=shared_outbox,
            )
            with pytest.raises(RuntimeError, match="Another sensor process owns this outbox"):
                worker2.__enter__()

            assert len(runner.calls) == calls_before
            status = fw1.helper_client.status()
            assert status["lease_active"] is True
            assert srv._lease_id == orig_lease
            assert len(status["active_block_ids"]) == 1

            rogue = FwHelperClient(sock_path)
            with pytest.raises(EnforcementError, match="active_lease_exists"):
                rogue.start()
            rogue.lease_id = str(uuid4())
            with pytest.raises(EnforcementError, match="invalid_or_expired_lease"):
                rogue.rollback("rogue_attempt")
            assert len(fw1.helper_client.status()["active_block_ids"]) == 1


def test_failed_rollback_preserves_tracking_retries_watchdog_and_blocks_false_reconcile(
        backend_runtime, sensor_headers, admin_headers, response_event_factory, tmp_path):
    import time

    sock_path = tmp_path / "fail_rb.sock"
    state = {"fail_delete": False, "delete_calls": 0}

    def flaky_runner(args, stdin_text=None):
        if list(args) == nft_rollback_command():
            state["delete_calls"] += 1
            if state["fail_delete"]:
                return 1, "simulated nft delete failure"
        return 0, ""

    class TrackTransport(ClientTransport):
        def __init__(self, app_client, headers):
            super().__init__(app_client, headers)
            self.reconcile_reasons = []

        def request(self, path, payload=None):
            res = super().request(path, payload)
            if path == "/api/sensor/reconcile":
                self.reconcile_reasons.append(payload.get("reason"))
            return res

    client = backend_runtime.client
    transport = TrackTransport(client, sensor_headers)
    alert_log = tmp_path / "fail_rb.jsonl"
    with FwHelperServer(socket_path=sock_path, protected=["10.0.0.1/32"], lease_seconds=30.0, runner=flaky_runner):
        fw = FirewallController(
            protected=["10.0.0.1/32"],
            mode="enforced",
            helper_client=FwHelperClient(sock_path),
        )
        worker = ResponseDispatcher(
            alert_log,
            policy=ResponsePolicy(min_flows=1),
            firewall=fw,
            api_url="http://127.0.0.1:8000",
            transport=transport,
        )
        with pytest.raises(RuntimeError, match="rollback failed"):
            with worker:
                worker.publish(response_event_factory(src_ip="10.10.0.50"))
                assert transport.ingested.wait(timeout=5)
                state["fail_delete"] = True

        assert len(fw._blocks) == 1
        assert fw.helper_client.lease_id is not None
        assert transport.reconcile_reasons == ["startup_rollback"]
        records = [json.loads(line) for line in alert_log.read_text().splitlines()]
        assert [rec.get("reason") for rec in records if rec.get("record_type") == "reconcile"] == ["startup_rollback"]
        assert client.get("/api/firewall/blocked?status=ROLLED_BACK", headers=admin_headers).json() == []
        assert len(client.get("/api/firewall/blocked?status=ACTIVE", headers=admin_headers).json()) == 1

        # Let watchdog hit a failing tick, then recover once nft deletion succeeds.
        deadline = time.monotonic() + 2.0
        while state["delete_calls"] < 2 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert fw.helper_client.status()["table_active"] is True
        state["fail_delete"] = False

        deadline = time.monotonic() + 2.0
        while fw.helper_client.status()["table_active"] and time.monotonic() < deadline:
            time.sleep(0.05)
        status = fw.helper_client.status()
        assert status["table_active"] is False
        assert status["lease_active"] is False
        assert len(status["rolled_back_block_ids"]) == 1


def test_helper_socket_permissions_ownership_and_symlink_refusal(tmp_path, monkeypatch):
    import os
    import pwd
    import stat

    sock_path = tmp_path / "subdir" / "fw.sock"
    runner = StubNftRunner()
    with FwHelperServer(
        socket_path=sock_path,
        runner=runner,
        socket_mode=0o660,
        dir_mode=0o750,
    ):
        assert stat.S_IMODE(sock_path.parent.stat().st_mode) == 0o750
        assert stat.S_IMODE(sock_path.stat().st_mode) == 0o660

    symlink_sock = tmp_path / "link.sock"
    symlink_sock.symlink_to(tmp_path / "target.sock")
    with pytest.raises(FileExistsError, match="symlink"):
        FwHelperServer(socket_path=symlink_sock, runner=runner).start()

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1001")
    sudo_server = FwHelperServer(socket_path=tmp_path / "sudo.sock", allowed_uids={0}, runner=runner)
    assert sudo_server._resolve_socket_ownership() == (1000, 1001)

    monkeypatch.setattr(pwd, "getpwuid", lambda uid: type("Pw", (), {"pw_gid": 2002})())
    explicit_server = FwHelperServer(socket_path=tmp_path / "uid.sock", allowed_uids={0, 2000}, runner=runner)
    assert explicit_server._resolve_socket_ownership() == (2000, 2002)

    # Shared system directories (/run) must never have their ownership or mode altered,
    # whereas dedicated application directories (/run/securenet) are configured for group access.
    from pathlib import Path
    import socket as _socket

    chown_calls = []
    chmod_calls = []
    monkeypatch.setattr(os, "chown", lambda p, u, g: chown_calls.append((Path(p), u, g)))
    monkeypatch.setattr(os, "chmod", lambda p, m: chmod_calls.append((Path(p), m)))
    monkeypatch.setattr(Path, "exists", lambda self: str(self) in ("/run", "/run/securenet"))
    monkeypatch.setattr(Path, "mkdir", lambda self, parents=False, exist_ok=False: None)
    monkeypatch.setattr(Path, "is_symlink", lambda self: False)
    monkeypatch.setattr(Path, "is_socket", lambda self: False)
    monkeypatch.setattr(
        Path,
        "stat",
        lambda self: type("St", (), {"st_uid": 0, "st_mode": stat.S_IFDIR | 0o755})(),
    )

    class DummySock:
        def bind(self, _addr): pass
        def listen(self, _backlog): pass
        def settimeout(self, _t): pass
        def accept(self): raise OSError("stopped")
        def close(self): pass

    monkeypatch.setattr(_socket, "socket", lambda *a, **kw: DummySock())

    shared_srv = FwHelperServer(socket_path="/run/fw_helper.sock", allowed_uids={0, 2000}, runner=runner)
    shared_srv.start()
    shared_srv.close()
    assert all(p != Path("/run") for p, _, _ in chown_calls)
    assert all(p != Path("/run") for p, _ in chmod_calls)
    assert (Path("/run/fw_helper.sock"), 2000, 2002) in chown_calls
    assert (Path("/run/fw_helper.sock"), 0o660) in chmod_calls

    chown_calls.clear()
    chmod_calls.clear()
    dedicated_srv = FwHelperServer(socket_path="/run/securenet/fw_helper.sock", allowed_uids={0, 2000}, runner=runner)
    dedicated_srv.start()
    dedicated_srv.close()
    assert (Path("/run/securenet"), 0, 2002) in chown_calls
    assert (Path("/run/securenet"), 0o750) in chmod_calls
    assert (Path("/run/securenet/fw_helper.sock"), 2000, 2002) in chown_calls


def test_failed_unblock_preserves_tracking_and_timeout_exception_retries_watchdog(
        tmp_path, manual_clock, monkeypatch):
    import subprocess
    import time

    sock_path = tmp_path / "unblock_retry.sock"
    runner = StubNftRunner()
    with FwHelperServer(
        socket_path=sock_path,
        protected=["10.0.0.1/32"],
        runner=runner,
        clock=manual_clock,
    ) as srv:
        # 1. Verify _default_runner normalizes subprocess.TimeoutExpired into (1, error)
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *a, **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired(cmd=["nft"], timeout=5)),
        )
        code, err = srv._default_runner(["nft", "list", "tables"])
        assert code == 1 and "TimeoutExpired" in err

        # 2. Failed unblock preserves tracking in both helper and controller; retry succeeds as 'unblocked'
        client = FwHelperClient(sock_path)
        fw = FirewallController(
            protected=["10.0.0.1/32"],
            mode="enforced",
            helper_client=client,
            clock=manual_clock,
        )
        fw.start()
        blocked = fw.block_ip("10.10.0.77", "PORTSCAN")
        block_id = blocked["block"]["block_id"]

        runner.fail_next = "simulated kernel delete failure"
        with pytest.raises(EnforcementError, match="nft_delete_failed"):
            fw.unblock_ip("10.10.0.77", block_id=block_id)

        assert "10.10.0.77" in fw._blocks
        assert client.status()["active_block_ids"] == [block_id]

        retried = fw.unblock_ip("10.10.0.77", block_id=block_id)
        assert retried["status"] == "unblocked"
        assert retried["command"] == nft_unblock_command("10.10.0.77")
        assert "10.10.0.77" not in fw._blocks
        assert client.status()["active_block_ids"] == []

    # 3. Watchdog thread survives subprocess.TimeoutExpired during lease expiry and retries on next tick
    timeout_sock = tmp_path / "timeout_wd.sock"
    wd_state = {"raise_timeout": False, "rollback_attempts": 0}

    def timeout_runner(args, stdin_text=None):
        if list(args) == nft_rollback_command() and wd_state["raise_timeout"]:
            wd_state["rollback_attempts"] += 1
            raise subprocess.TimeoutExpired(cmd=args, timeout=5)
        return 0, ""

    with FwHelperServer(
        socket_path=timeout_sock,
        protected=["10.0.0.1/32"],
        lease_seconds=0.2,
        runner=timeout_runner,
    ) as wd_srv:
        wd_client = FwHelperClient(timeout_sock)
        wd_client.start()
        b_id = str(uuid4())
        assert wd_client.block("10.10.0.88", 60, block_id=b_id)["status"] == "blocked"
        wd_state["raise_timeout"] = True

        deadline = time.monotonic() + 2.0
        while wd_state["rollback_attempts"] < 1 and time.monotonic() < deadline:
            time.sleep(0.05)

        assert wd_srv._thread.is_alive()
        assert wd_srv._table_active is True
        assert b_id in [v["block_id"] for v in wd_srv._active.values()]

        wd_state["raise_timeout"] = False
        deadline = time.monotonic() + 2.0
        while wd_srv._table_active and time.monotonic() < deadline:
            time.sleep(0.05)

        status = wd_client.status()
        assert status["table_active"] is False
        assert status["lease_active"] is False
        assert status["rolled_back_block_ids"] == [b_id]


def test_stats_keep_enforced_mode_during_pending_unblock_and_expiry(
        backend_runtime, sensor_headers, admin_headers, response_event_factory):
    from datetime import datetime, timedelta, timezone
    from backend.models import BlockedIP

    client = backend_runtime.client
    block_id = str(uuid4())
    now = datetime.now(timezone.utc)
    body = {
        "event": response_event_factory(src_ip="10.10.0.60").to_dict(),
        "decision": {"action": "candidate", "reason": "repeated_high_score_flows", "evidence_count": 3},
        "firewall": {
            "mode": "enforced",
            "ip": "10.10.0.60",
            "threat": "PORTSCAN",
            "status": "blocked",
            "block": {
                "block_id": block_id,
                "ip": "10.10.0.60",
                "threat": "PORTSCAN",
                "mode": "enforced",
                "blocked_at": now.isoformat(),
                "unblock_at": (now + timedelta(minutes=15)).isoformat(),
            },
            "command": nft_block_command("10.10.0.60", 900),
        },
    }
    assert client.post("/api/alerts/ingest", json=body, headers=sensor_headers).status_code == 201
    assert client.post(f"/api/firewall/unblock/10.10.0.60?block_id={block_id}", headers=admin_headers).status_code == 202

    pending_stats = client.get("/api/stats", headers=admin_headers).json()
    assert pending_stats["active_blocked_ips"] == 1
    assert pending_stats["active_simulated_blocks"] == 0
    assert pending_stats["response_mode"] == "enforced"
    assert pending_stats["pending_unblocks"] == 1

    with backend_runtime.app.state.session_factory() as db:
        row = db.query(BlockedIP).filter(BlockedIP.block_id == block_id).one()
        row.status = "EXPIRY_PENDING"
        db.commit()

    expiry_stats = client.get("/api/stats", headers=admin_headers).json()
    assert expiry_stats["active_blocked_ips"] == 1
    assert expiry_stats["response_mode"] == "enforced"

    assert client.post(
        "/api/sensor/reconcile",
        json={"mode": "enforced", "active_block_ids": [], "reason": "shutdown_rollback"},
        headers=sensor_headers,
    ).status_code == 200
    cleared_stats = client.get("/api/stats", headers=admin_headers).json()
    assert cleared_stats["active_blocked_ips"] == 0
    assert cleared_stats["response_mode"] == "dry_run"


def test_sniffer_sigterm_exits_cleanly_with_response_summary(
        tmp_path, isolated_project, train_dataset, dataset_cases):
    from hashlib import sha256
    import os
    import subprocess
    import sys
    from scapy.all import Ether, IP, TCP, wrpcap

    run = train_dataset(next(case for case in dataset_cases if case.name == "unified"))
    pcap_path = tmp_path / "sigterm.pcap"
    wrpcap(str(pcap_path), [Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                          / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")])
    # A subprocess does not inherit the fixture's in-process path monkeypatch.
    bootstrap = (
        "import runpy, sys; from pathlib import Path; from ml_engine import datasets; "
        "datasets.PROJECT_ROOT = Path(sys.argv.pop(1)); "
        "runpy.run_module('sniffer.main', run_name='__main__')"
    )
    proc = subprocess.Popen(
        [
            sys.executable, "-c", bootstrap, str(isolated_project),
            "-r", str(pcap_path),
            "--predict", "--respond",
            "--linger-seconds", "30",
            "--alert-log", str(tmp_path / "sigterm_alerts.jsonl"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, "SECURENET_MODEL_SHA256": sha256(run.bundle_path.read_bytes()).hexdigest()},
    )
    try:
        collected = []
        for line in proc.stderr:
            collected.append(line)
            if "Replay complete; sensor stays available" in line:
                break
        assert any("Replay complete; sensor stays available" in line for line in collected), "".join(collected)
        proc.terminate()
        _, rest_err = proc.communicate(timeout=10)
        full_err = "".join(collected) + (rest_err or "")
        assert proc.returncode == 0
        assert "Response summary:" in full_err
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_demo_up_rejects_invalid_args_and_cleans_up_on_sensor_failure(tmp_path):
    import os
    import shutil
    import subprocess
    import time

    res = subprocess.run(["sh", "scripts/demo_up.sh", "--unknown-flag"], capture_output=True, text=True)
    assert res.returncode == 2
    assert "Unknown option" in res.stderr

    # Isolated temporary workspace so configured PostgreSQL/runtime files are untouched.
    (tmp_path / "scripts").mkdir()
    (tmp_path / "backend").mkdir()
    (tmp_path / "frontend" / "dist").mkdir(parents=True)
    (tmp_path / "runtime").mkdir()
    (tmp_path / ".venv" / "bin").mkdir(parents=True)
    shutil.copy("scripts/demo_up.sh", tmp_path / "scripts" / "demo_up.sh")
    (tmp_path / "backend" / ".env").write_text("# stub\n")
    (tmp_path / "frontend" / "dist" / "index.html").write_text("<html></html>\n")
    (tmp_path / "runtime" / "sensor.env").write_text("SENSOR_API_TOKEN=" + "s" * 32 + "\nSENSOR_ID=s1\n")
    (tmp_path / "sample.pcap").write_bytes(b"stub")

    fake_python = tmp_path / ".venv" / "bin" / "python"
    fake_python.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys, urllib.request\n"
        "if len(sys.argv) == 3 and sys.argv[1].count('.') == 3 and sys.argv[2].isdigit():\n"
        "    url = f'http://{sys.argv[1]}:{sys.argv[2]}/api/health'\n"
        "    data = json.loads(urllib.request.urlopen(url, timeout=1).read())\n"
        "    raise SystemExit(0 if data.get('service') == 'SecureNet AI Backend' else 1)\n"
        "if 'sniffer.main' in sys.argv:\n"
        "    sys.stderr.write('forced sensor startup failure\\n')\n"
        "    raise SystemExit(1)\n"
        "raise SystemExit(0)\n"
    )
    fake_python.chmod(0o755)

    fake_uvicorn = tmp_path / ".venv" / "bin" / "uvicorn"
    fake_uvicorn.write_text(
        "#!/usr/bin/env python3\n"
        "import http.server, json, signal, sys\n"
        "port = int(sys.argv[sys.argv.index('--port') + 1])\n"
        "class H(http.server.BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200)\n"
        "        self.end_headers()\n"
        "        self.wfile.write(json.dumps({'service': 'SecureNet AI Backend'}).encode())\n"
        "    def log_message(self, *a): pass\n"
        "srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), H)\n"
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
        "srv.serve_forever()\n"
    )
    fake_uvicorn.chmod(0o755)

    # Pick an ephemeral localhost port for the stub uvicorn health check.
    import socket as _sock
    with _sock.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    run = subprocess.run(
        ["sh", str(tmp_path / "scripts" / "demo_up.sh"), "-r", str(tmp_path / "sample.pcap")],
        env={**os.environ, "API_PORT": str(port)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert run.returncode == 1
    assert "forced sensor startup failure" in run.stderr
    assert not (tmp_path / "runtime" / "demo_api.pid").exists()
    assert not (tmp_path / "runtime" / "demo_sensor.pid").exists()
    # Ensure started stub uvicorn is no longer listening.
    time.sleep(0.05)
    with _sock.socket() as probe:
        assert probe.connect_ex(("127.0.0.1", port)) != 0
