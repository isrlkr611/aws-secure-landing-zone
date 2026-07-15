
import pytest

from detectors.base import DetectionResult, Detector
from detectors.null_detector import NullDetector
from orchestrator import run_all, run_technique


class AlwaysDetectDetector(Detector):
    name = "always"

    def check(self, technique_id, started_at, finished_at):
        return DetectionResult(detected=True, detector_name=self.name, evidence="stub: always detects")


FAKE_TECHNIQUE = {
    "attack_technique": "T9999",
    "display_name": "Fake Test Technique",
    "tactic": "discovery",
    "safety": "read_only",
    "test": {"command": "echo hello-purple-team"},
}


def test_run_technique_dry_run_does_not_execute():
    result = run_technique(FAKE_TECHNIQUE, NullDetector(), dry_run=True)
    assert result.executed is False
    assert result.skip_reason == "dry-run"
    assert result.exit_code is None
    assert result.detected is None


def test_run_technique_executes_and_captures_exit_code():
    result = run_technique(FAKE_TECHNIQUE, NullDetector(), dry_run=False)
    assert result.executed is True
    assert result.exit_code == 0


def test_run_technique_reports_detection_from_detector():
    result = run_technique(FAKE_TECHNIQUE, AlwaysDetectDetector(), dry_run=False)
    assert result.detected is True
    assert result.detector_name == "always"


def test_run_all_refuses_unknown_target(tmp_path):
    config = tmp_path / "lab-config.yaml"
    config.write_text("hosts:\n  - name: localhost\n    address: 127.0.0.1\n    confirmed_own_lab: true\n")
    with pytest.raises(KeyError):
        run_all("not-a-real-host", NullDetector(), lab_config_path=config)


def test_run_all_refuses_unconfirmed_remote_target(tmp_path):
    config = tmp_path / "lab-config.yaml"
    config.write_text("hosts:\n  - name: some-remote\n    address: 10.9.9.9\n")  # no confirmed_own_lab
    with pytest.raises(PermissionError):
        run_all("some-remote", NullDetector(), lab_config_path=config)


def test_run_all_against_localhost_runs_real_curated_techniques():
    results = run_all("localhost", NullDetector())
    assert len(results) >= 5  # the curated atomics/ set
    assert all(r.executed for r in results)
    # NullDetector always reports not-detected, by design
    assert all(r.detected is False for r in results)


def test_run_all_technique_filter_restricts_to_requested_ids():
    results = run_all("localhost", NullDetector(), technique_filter=["T1082"])
    assert len(results) == 1
    assert results[0].technique_id == "T1082"


def test_run_all_dry_run_does_not_require_lab_gate(tmp_path):
    # dry-run must be safe to invoke even against an unconfirmed host,
    # since nothing is actually executed - it's purely informational.
    config = tmp_path / "lab-config.yaml"
    config.write_text("hosts:\n  - name: some-remote\n    address: 10.9.9.9\n")
    results = run_all("some-remote", NullDetector(), lab_config_path=config, dry_run=True)
    assert all(not r.executed for r in results)
