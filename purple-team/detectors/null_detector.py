"""Default detector when no detection stack is configured.

Deliberately returns `detected=False` with an evidence string explaining
*why* (not configured), rather than raising or returning some ambiguous
"unknown" state - the coverage report needs to be able to say "0% because
nothing is watching" clearly, as opposed to "0% because the detection
stack watched and missed every technique." Those are very different
findings and this repo has no live detection stack deployed (see
docs/architecture.md - the whole landing zone is validated/scanned but
not deployed), so being honest about which case we're in matters more
here than usual.
"""

from __future__ import annotations

from datetime import datetime

from detectors.base import DetectionResult, Detector


class NullDetector(Detector):
    name = "null"

    def check(self, technique_id: str, started_at: datetime, finished_at: datetime) -> DetectionResult:
        return DetectionResult(
            detected=False,
            detector_name=self.name,
            evidence="No detection stack configured - see purple-team/README.md 'Detectors'.",
        )
