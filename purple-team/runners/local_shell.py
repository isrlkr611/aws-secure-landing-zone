"""Executes a technique's test command locally via subprocess.

"Local" here means "on whatever host this orchestrator process itself runs
on" - safety.require_lab_target() is what decides whether that's an
allowed target at all; this module just executes and captures output once
that gate has already passed.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    started_at: datetime
    finished_at: datetime


def run_command(command: str, timeout: int = 30) -> CommandResult:
    started_at = datetime.now(timezone.utc)
    proc = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    finished_at = datetime.now(timezone.utc)
    return CommandResult(
        command=command,
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        started_at=started_at,
        finished_at=finished_at,
    )
