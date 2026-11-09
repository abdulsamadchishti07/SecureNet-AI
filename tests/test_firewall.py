"""Firewall simulation contracts; no subprocess or root privileges required."""

import subprocess

import pytest

from backend.firewall import FirewallController


@pytest.fixture(autouse=True)
def forbid_command_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Firewall simulation attempted a real command")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("ip", ["127.0.0.1", "127.4.5.6", "0.0.0.0", "169.254.2.3",
                                "224.0.0.1", "255.255.255.255", "10.0.0.1", "10.1.2.3"])
def test_builtin_and_configured_protection(ip):
    firewall = FirewallController(protected=["10.0.0.1", "10.1.2.0/24"])
    assert firewall.is_whitelisted(ip)
    assert firewall.block_ip(ip, "PORTSCAN")["status"] == "protected"
    assert firewall.list_active_blocks() == []


@pytest.mark.parametrize("ip", ["bad", "::1", "1.2.3.4; echo hacked", "-s", "999.2.3.4", 1, None])
def test_invalid_targets_are_rejected(ip):
    with pytest.raises(ValueError):
        FirewallController().block_ip(ip, "PORTSCAN")


def test_simulated_block_is_idempotent_and_expires_without_sleep(manual_clock):
    firewall = FirewallController(duration_seconds=15, clock=manual_clock)
    first = firewall.block_ip("10.10.0.9", "PORTSCAN")
    assert first["status"] == "would_block"
    assert first["command"] == ["iptables", "-w", "2", "-A", "INPUT", "-s", "10.10.0.9",
                                 "-m", "comment", "--comment", "securenet-ai", "-j", "DROP"]
    assert firewall.block_ip("10.10.0.9", "DOS")["status"] == "already_simulated"
    assert len(firewall.list_active_blocks()) == 1
    first["block"]["ip"] = "mutated"
    assert firewall.list_active_blocks()[0]["ip"] == "10.10.0.9"
    manual_clock.advance(14)
    assert firewall.expire() == []
    manual_clock.advance(1)
    (expired,) = firewall.expire()
    assert expired["command"][3] == "-D"
    assert expired["status"] == "would_unblock"
    assert expired["reason"] == "expired"
    assert firewall.expire() == firewall.list_active_blocks() == []
    assert firewall.block_ip("10.10.0.9", "DOS")["status"] == "would_block"


def test_capacity_and_manual_unblock_are_explicit():
    firewall = FirewallController(max_blocks=1)
    firewall.block_ip("10.10.0.9", "DOS")
    assert firewall.block_ip("10.10.0.8", "DOS")["status"] == "capacity_reached"
    assert firewall.unblock_ip("10.10.0.9")["status"] == "would_unblock"
    assert firewall.unblock_ip("10.10.0.9")["status"] == "not_simulated"
    with pytest.raises(ValueError):
        firewall.block_ip("10.10.0.8", "BENIGN")


@pytest.mark.parametrize("options", [{"protected": ["invalid"]}, {"duration_seconds": 0},
                                     {"duration_seconds": float("inf")}, {"max_blocks": 0}])
def test_invalid_configuration_is_rejected(options):
    with pytest.raises(ValueError):
        FirewallController(**options)


def test_old_unblock_command_cannot_remove_new_block_for_same_ip():
    firewall = FirewallController()
    original = firewall.block_ip("10.10.0.9", "PORTSCAN")["block"]["block_id"]
    firewall.unblock_ip("10.10.0.9")
    replacement = firewall.block_ip("10.10.0.9", "DOS")["block"]["block_id"]
    action = firewall.unblock_ip("10.10.0.9", block_id=original)
    assert action["status"] == "stale_block"
    assert firewall.list_active_blocks()[0]["block_id"] == replacement
