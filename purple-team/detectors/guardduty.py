"""AWS GuardDuty detector - best-effort correlation, not exact.

Important limitation documented up front rather than glossed over:
GuardDuty finding *types* (e.g. "Recon:EC2/PortProbeUnprotectedPort") are
not MITRE-ATT&CK-technique-tagged by AWS the way Wazuh's ruleset tags
`rule.mitre.id`. This detector does the best correlation available -
a small, explicit, admittedly-incomplete map from technique ID to a
GuardDuty finding-type prefix for the handful of techniques where a
reasonably confident mapping exists, and otherwise reports "no mapping
known" rather than guessing or silently matching on nothing.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from detectors.base import DetectionResult, Detector

# Deliberately small and explicit. Extend only with mappings you can point
# to AWS's own GuardDuty finding-types documentation for - a wrong mapping
# here is worse than "no mapping known", since it would make a real gap in
# detection coverage look like a covered technique.
TECHNIQUE_TO_FINDING_TYPE_PREFIX: dict[str, str] = {
    "T1018": "Recon:EC2/Port",  # remote system/service discovery via port probing
    "T1046": "Recon:EC2/Port",  # network service discovery
}

DEFAULT_GRACE_PERIOD_SECONDS = 120


class GuardDutyDetector(Detector):
    name = "guardduty"

    def __init__(
        self,
        detector_id: str,
        region_name: str = "eu-west-3",
        boto3_client=None,
        grace_period_seconds: int = DEFAULT_GRACE_PERIOD_SECONDS,
    ) -> None:
        self.detector_id = detector_id
        self.grace_period = timedelta(seconds=grace_period_seconds)
        if boto3_client is not None:
            self.client = boto3_client
        else:
            import boto3

            self.client = boto3.client("guardduty", region_name=region_name)

    def check(self, technique_id: str, started_at: datetime, finished_at: datetime) -> DetectionResult:
        finding_type_prefix = TECHNIQUE_TO_FINDING_TYPE_PREFIX.get(technique_id)
        if finding_type_prefix is None:
            return DetectionResult(
                detected=False,
                detector_name=self.name,
                evidence=f"No GuardDuty finding-type mapping known for {technique_id} - see TECHNIQUE_TO_FINDING_TYPE_PREFIX.",
            )

        window_end = finished_at + self.grace_period
        response = self.client.list_findings(
            DetectorId=self.detector_id,
            FindingCriteria={
                "Criterion": {
                    "type": {"Eq": [finding_type_prefix]},
                    "updatedAt": {
                        "Gte": int(started_at.timestamp() * 1000),
                        "Lte": int(window_end.timestamp() * 1000),
                    },
                }
            },
        )
        finding_ids = response.get("FindingIds", [])
        if not finding_ids:
            return DetectionResult(
                detected=False,
                detector_name=self.name,
                evidence=f"No GuardDuty finding of type '{finding_type_prefix}*' in window.",
            )

        return DetectionResult(
            detected=True,
            detector_name=self.name,
            evidence=f"GuardDuty finding(s) {finding_ids} of type '{finding_type_prefix}*'",
        )
