#!/usr/bin/env python3
"""Runs the curated Atomic Red Team-style techniques in atomics/ against an
authorized lab target, asks a Detector whether each run was observed, and
produces a pass/fail detection-coverage report.

Usage:
    python3 orchestrator.py --target localhost --detector null \
        --output-md reports/purple-team-report.md \
        --output-json reports/purple-team-report.json

    python3 orchestrator.py --dry-run   # list techniques, run nothing

Only ever touches a target that passes safety.require_lab_target() - see
safety.py for why, and lab-config.yaml for the current allowlist.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from detectors.base import Detector
from detectors.null_detector import NullDetector
from runners.local_shell import run_command
from safety import DEFAULT_LAB_CONFIG, load_lab_config, require_lab_target

ATOMICS_DIR = Path(__file__).resolve().parent / "atomics"


@dataclass
class TechniqueResult:
    technique_id: str
    display_name: str
    tactic: str
    command: str
    executed: bool
    exit_code: int | None
    detected: bool | None
    detector_name: str | None
    evidence: str | None
    skip_reason: str | None = None


def load_techniques(directory: Path = ATOMICS_DIR) -> list[dict]:
    techniques = []
    for path in sorted(directory.glob("T*.yaml")):
        techniques.append(yaml.safe_load(path.read_text()))
    return techniques


def run_technique(technique: dict, detector: Detector, dry_run: bool = False) -> TechniqueResult:
    technique_id = technique["attack_technique"]
    command = technique["test"]["command"]

    if dry_run:
        return TechniqueResult(
            technique_id=technique_id,
            display_name=technique["display_name"],
            tactic=technique["tactic"],
            command=command,
            executed=False,
            exit_code=None,
            detected=None,
            detector_name=None,
            evidence=None,
            skip_reason="dry-run",
        )

    result = run_command(command)
    detection = detector.check(technique_id, result.started_at, result.finished_at)

    return TechniqueResult(
        technique_id=technique_id,
        display_name=technique["display_name"],
        tactic=technique["tactic"],
        command=command,
        executed=True,
        exit_code=result.exit_code,
        detected=detection.detected,
        detector_name=detection.detector_name,
        evidence=detection.evidence,
    )


def run_all(
    target_name: str,
    detector: Detector,
    lab_config_path: Path = DEFAULT_LAB_CONFIG,
    dry_run: bool = False,
    technique_filter: list[str] | None = None,
) -> list[TechniqueResult]:
    hosts = load_lab_config(lab_config_path)
    if target_name not in hosts:
        raise KeyError(f"'{target_name}' is not defined in {lab_config_path} - add it to the hosts: list first.")
    host = hosts[target_name]

    if not dry_run:
        require_lab_target(host)  # the gate - see safety.py

    techniques = load_techniques()
    if technique_filter:
        techniques = [t for t in techniques if t["attack_technique"] in technique_filter]

    return [run_technique(t, detector, dry_run=dry_run) for t in techniques]


def build_detector(name: str) -> Detector:
    if name == "null":
        return NullDetector()
    if name == "wazuh":
        raise NotImplementedError(
            "Wazuh detector requires --wazuh-url/--wazuh-user/--wazuh-password "
            "or programmatic construction - see detectors/wazuh.py."
        )
    if name == "guardduty":
        raise NotImplementedError(
            "GuardDuty detector requires --guardduty-detector-id and AWS "
            "credentials - see detectors/guardduty.py."
        )
    raise ValueError(f"Unknown detector: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="localhost")
    parser.add_argument("--detector", default="null", choices=["null", "wazuh", "guardduty"])
    parser.add_argument("--lab-config", type=Path, default=DEFAULT_LAB_CONFIG)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--technique", action="append", default=None, help="Restrict to specific technique ID(s), repeatable")
    parser.add_argument("--output-md", type=Path, default=None)
    parser.add_argument("--output-json", type=Path, default=None)
    args = parser.parse_args()

    detector = build_detector(args.detector)

    try:
        results = run_all(
            args.target,
            detector,
            lab_config_path=args.lab_config,
            dry_run=args.dry_run,
            technique_filter=args.technique,
        )
    except (PermissionError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)

    from report import render_json, render_markdown

    markdown = render_markdown(results, target=args.target, detector_name=detector.name, dry_run=args.dry_run)
    if args.output_md:
        args.output_md.write_text(markdown)
        print(f"Wrote {args.output_md}", file=sys.stderr)
    else:
        print(markdown)

    if args.output_json:
        args.output_json.write_text(json.dumps(render_json(results), indent=2, default=str))
        print(f"Wrote {args.output_json}", file=sys.stderr)


if __name__ == "__main__":
    main()
