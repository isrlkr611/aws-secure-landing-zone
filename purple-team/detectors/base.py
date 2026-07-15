"""Detector interface: "did the detection stack notice this technique run?"

Kept deliberately narrow - a Detector answers one question (was there a
matching alert in this time window) so the orchestrator can treat
GuardDuty, Wazuh, Suricata, or "nothing configured" identically. Coverage
% is a property of *this interface*, not of any one backend.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime


@dataclass
class DetectionResult:
    detected: bool
    detector_name: str
    evidence: str | None = None


class Detector(ABC):
    name: str = "detector"

    @abstractmethod
    def check(self, technique_id: str, started_at: datetime, finished_at: datetime) -> DetectionResult:
        """Return whether this detector observed an alert for `technique_id`
        within [started_at, finished_at] (plus each implementation's own
        reasonable grace window for alert-pipeline latency).
        """
        raise NotImplementedError
