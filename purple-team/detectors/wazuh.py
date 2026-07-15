"""Wazuh detector - queries the Wazuh indexer (OpenSearch) for alerts whose
rule carries a matching MITRE ATT&CK technique ID within the run window.

Not exercised against a live Wazuh instance in this repo (none is
deployed - see docs/architecture.md), but is real, complete code, unit
tested against a mocked HTTP response shaped like Wazuh's actual index
schema (`rule.mitre.id` is a real field Wazuh populates for MITRE-mapped
rules as of Wazuh 4.x).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import httpx

from detectors.base import DetectionResult, Detector

# Alert pipelines have latency (log shipping, indexing) - a technique that
# ran at T and was detected at T+8s should still count as a hit.
DEFAULT_GRACE_PERIOD_SECONDS = 60


class WazuhDetector(Detector):
    name = "wazuh"

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        index_pattern: str = "wazuh-alerts-*",
        verify_tls: bool = True,
        grace_period_seconds: int = DEFAULT_GRACE_PERIOD_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.index_pattern = index_pattern
        self.grace_period = timedelta(seconds=grace_period_seconds)
        self._owns_client = client is None
        self.client = client or httpx.Client(verify=verify_tls, auth=(username, password))

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def check(self, technique_id: str, started_at: datetime, finished_at: datetime) -> DetectionResult:
        window_start = started_at
        window_end = finished_at + self.grace_period

        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"rule.mitre.id": technique_id}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": window_start.isoformat(),
                                    "lte": window_end.isoformat(),
                                }
                            }
                        },
                    ]
                }
            },
            "size": 1,
        }

        response = self.client.post(f"{self.base_url}/{self.index_pattern}/_search", json=query, timeout=15)
        response.raise_for_status()
        body = response.json()
        hits = body.get("hits", {}).get("hits", [])

        if not hits:
            return DetectionResult(detected=False, detector_name=self.name, evidence="No matching Wazuh alert in window.")

        alert = hits[0]["_source"]
        rule_desc = alert.get("rule", {}).get("description", "unknown rule")
        return DetectionResult(
            detected=True,
            detector_name=self.name,
            evidence=f"Wazuh alert: rule '{rule_desc}' at {alert.get('@timestamp')}",
        )
