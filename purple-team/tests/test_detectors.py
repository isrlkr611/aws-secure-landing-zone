from datetime import datetime, timezone
from unittest.mock import MagicMock

import httpx
import respx

from detectors.guardduty import GuardDutyDetector
from detectors.null_detector import NullDetector
from detectors.wazuh import WazuhDetector


def test_null_detector_never_detects_and_says_why():
    detector = NullDetector()
    result = detector.check("T1082", datetime.now(timezone.utc), datetime.now(timezone.utc))
    assert result.detected is False
    assert "No detection stack configured" in result.evidence


@respx.mock
def test_wazuh_detector_reports_hit_when_matching_alert_found():
    respx.post("https://wazuh.example.com/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "@timestamp": "2026-01-01T00:00:05Z",
                                "rule": {"description": "System discovery command executed"},
                            }
                        }
                    ]
                }
            },
        )
    )
    detector = WazuhDetector(base_url="https://wazuh.example.com", username="u", password="p")
    result = detector.check("T1082", datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc))
    assert result.detected is True
    assert "System discovery" in result.evidence
    detector.close()


@respx.mock
def test_wazuh_detector_reports_miss_when_no_alert_found():
    respx.post("https://wazuh.example.com/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"hits": []}})
    )
    detector = WazuhDetector(base_url="https://wazuh.example.com", username="u", password="p")
    result = detector.check("T1082", datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc))
    assert result.detected is False
    detector.close()


def test_guardduty_detector_returns_no_mapping_for_unmapped_technique():
    detector = GuardDutyDetector(detector_id="abc123", boto3_client=MagicMock())
    result = detector.check("T1082", datetime.now(timezone.utc), datetime.now(timezone.utc))
    assert result.detected is False
    assert "No GuardDuty finding-type mapping known" in result.evidence


def test_guardduty_detector_reports_hit_for_mapped_technique_with_findings():
    mock_client = MagicMock()
    mock_client.list_findings.return_value = {"FindingIds": ["finding-1"]}
    detector = GuardDutyDetector(detector_id="abc123", boto3_client=mock_client)
    result = detector.check("T1018", datetime.now(timezone.utc), datetime.now(timezone.utc))
    assert result.detected is True
    assert "finding-1" in result.evidence
    mock_client.list_findings.assert_called_once()


def test_guardduty_detector_reports_miss_for_mapped_technique_no_findings():
    mock_client = MagicMock()
    mock_client.list_findings.return_value = {"FindingIds": []}
    detector = GuardDutyDetector(detector_id="abc123", boto3_client=mock_client)
    result = detector.check("T1018", datetime.now(timezone.utc), datetime.now(timezone.utc))
    assert result.detected is False
