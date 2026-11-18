"""The lab refuses host execution and exposes detection gaps as failing acceptance."""

import json
from types import SimpleNamespace

import pytest

from scripts import netns_multi_attack_lab as lab


@pytest.mark.parametrize("arguments", [["--parent-netns", "different"],
    ["--traffic", "DOS", "--source", "10.210.0.4"], ["--probe", "10.210.0.2"]])
def test_lab_refuses_existing_host_interfaces_before_any_mutation(monkeypatch, arguments):
    commands = []
    def read_only(args, **kwargs):
        commands.append(args)
        assert args == ["ip", "-j", "link", "show"]
        return SimpleNamespace(stdout=json.dumps([{"ifname": "lo"}, {"ifname": "eth0"}]))
    monkeypatch.setattr(lab, "command", read_only)
    with pytest.raises(SystemExit) as error:
        lab.main(arguments)
    assert error.value.code == 2
    assert len(commands) == 1


def test_strict_lab_acceptance_exits_two_for_misses_and_writes_report(monkeypatch, tmp_path):
    monkeypatch.setattr(lab, "command", lambda *args, **kwargs: SimpleNamespace(stdout='[{"ifname":"lo"}]'))
    class SimulatedLab:
        def __init__(self, work):
            self.work = work
        def setup(self):
            pass
        def scenario(self, vector, ip, seconds):
            return {"vector": vector, "status": "missed"}
        def watchdog(self):
            return {"sigkill_rollback_recovered": True}
        def close(self):
            pass
    monkeypatch.setattr(lab, "Lab", SimulatedLab)
    # Avoid any dependency on locally installed models in this source-only guard test.
    monkeypatch.setattr(lab.Path, "read_bytes", lambda path: b"fixture")
    output = tmp_path / "result.json"
    with pytest.raises(SystemExit) as error:
        lab.main(["--parent-netns", "different", "--require-all-detected", "--output", str(output)])
    assert error.value.code == 2
    report = json.loads(output.read_text())
    assert report["status"] == "completed_with_detection_gaps"
    assert len(report["scenarios"]) == 3 and all(r["status"] == "missed" for r in report["scenarios"])
