"""Unit tests for the mapping/scoring logic in generate_report.py.

Uses small, synthetic fixtures rather than the repo's real 61-check
mapping or a real terraform scan - these tests are about proving the
aggregation math and the "unmapped checks are surfaced, not dropped"
behavior are correct, independent of how many checks happen to be in
mapping_norms.yaml on any given day.
"""

import generate_report as gr

FIXTURE_THEMES = {
    "network": {
        "title": "Network exposure",
        "checks": ["CKV_FAKE_1", "CKV_FAKE_2"],
        "frameworks": {
            "iso27001": [{"clause": "A.8.20", "title": "Networks security"}],
            "pci_dss": [{"clause": "Requirement 1", "title": "Network security controls"}],
        },
    },
    "encryption": {
        "title": "Encryption at rest",
        "checks": ["CKV_FAKE_3"],
        "frameworks": {
            "iso27001": [{"clause": "A.8.24", "title": "Use of cryptography"}],
        },
    },
}


def _fixture_check_to_themes():
    check_to_themes = {}
    for theme_key, theme in FIXTURE_THEMES.items():
        for check_id in theme["checks"]:
            check_to_themes.setdefault(check_id, []).append(theme_key)
    return check_to_themes


def _entry(check_id, resource="module.x.resource.y", suppress_comment=None):
    return {
        "check_id": check_id,
        "check_name": f"fake check {check_id}",
        "resource": resource,
        "check_result": {"suppress_comment": suppress_comment} if suppress_comment else {},
    }


def test_build_report_counts_passed_failed_skipped_per_framework():
    checkov_report = {
        "results": {
            "passed_checks": [_entry("CKV_FAKE_1"), _entry("CKV_FAKE_3")],
            "failed_checks": [_entry("CKV_FAKE_2")],
            "skipped_checks": [_entry("CKV_FAKE_1", suppress_comment="accepted risk")],
        },
        "summary": {"passed": 2, "failed": 1, "skipped": 1},
    }
    report = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)

    iso = report["framework_stats"]["iso27001"]
    assert iso.passed == 2
    assert iso.failed == 1
    assert iso.skipped == 1

    pci = report["framework_stats"]["pci_dss"]
    # pci_dss is only mapped from the "network" theme (CKV_FAKE_1, CKV_FAKE_2)
    assert pci.passed == 1
    assert pci.failed == 1
    assert pci.skipped == 1


def test_compliance_pct_excludes_skipped_from_denominator():
    checkov_report = {
        "results": {
            "passed_checks": [_entry("CKV_FAKE_1")],
            "failed_checks": [],
            "skipped_checks": [_entry("CKV_FAKE_1"), _entry("CKV_FAKE_1")],
        },
        "summary": {},
    }
    report = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    iso = report["framework_stats"]["iso27001"]
    # 1 passed, 0 failed, 2 skipped -> evaluated = 1 (skipped excluded), pct = 100%
    assert iso.evaluated == 1
    assert iso.compliance_pct == 100.0


def test_compliance_pct_is_none_when_nothing_evaluated():
    checkov_report = {
        "results": {
            "passed_checks": [],
            "failed_checks": [],
            "skipped_checks": [_entry("CKV_FAKE_1")],
        },
        "summary": {},
    }
    report = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    iso = report["framework_stats"]["iso27001"]
    assert iso.evaluated == 0
    assert iso.compliance_pct is None


def test_unmapped_checks_are_surfaced_not_dropped():
    checkov_report = {
        "results": {
            "passed_checks": [_entry("CKV_FAKE_1"), _entry("CKV_TOTALLY_UNMAPPED")],
            "failed_checks": [],
            "skipped_checks": [],
        },
        "summary": {},
    }
    report = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    assert report["unmapped_checks"] == {"CKV_TOTALLY_UNMAPPED": 1}
    # and it must NOT have silently contributed to any framework's stats
    assert report["framework_stats"]["iso27001"].passed == 1


def test_a_check_mapped_to_two_frameworks_counts_in_both():
    checkov_report = {
        "results": {
            "passed_checks": [_entry("CKV_FAKE_1")],
            "failed_checks": [],
            "skipped_checks": [],
        },
        "summary": {},
    }
    report = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    # CKV_FAKE_1 belongs to "network", which maps to both iso27001 and pci_dss
    assert report["framework_stats"]["iso27001"].passed == 1
    assert report["framework_stats"]["pci_dss"].passed == 1


def test_render_markdown_includes_unmapped_section_only_when_present():
    checkov_report = {
        "results": {
            "passed_checks": [_entry("CKV_FAKE_1")],
            "failed_checks": [],
            "skipped_checks": [],
        },
        "summary": {"passed": 1, "failed": 0, "skipped": 0},
    }
    report = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    markdown = gr.render_markdown(report, FIXTURE_THEMES)
    assert "## Unmapped checks" not in markdown

    checkov_report["results"]["passed_checks"].append(_entry("CKV_UNMAPPED_X"))
    report2 = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    markdown2 = gr.render_markdown(report2, FIXTURE_THEMES)
    assert "## Unmapped checks" in markdown2
    assert "CKV_UNMAPPED_X" in markdown2


def test_render_markdown_lists_gaps_only_when_failures_exist():
    checkov_report = {
        "results": {
            "passed_checks": [_entry("CKV_FAKE_1")],
            "failed_checks": [],
            "skipped_checks": [],
        },
        "summary": {},
    }
    report = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    assert "## Gaps" not in gr.render_markdown(report, FIXTURE_THEMES)

    checkov_report["results"]["failed_checks"] = [_entry("CKV_FAKE_2", resource="module.bad.thing")]
    report2 = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    markdown = gr.render_markdown(report2, FIXTURE_THEMES)
    assert "## Gaps (failed checks)" in markdown
    assert "module.bad.thing" in markdown


def test_render_json_is_serializable_and_matches_stats():
    checkov_report = {
        "results": {
            "passed_checks": [_entry("CKV_FAKE_1")],
            "failed_checks": [_entry("CKV_FAKE_2")],
            "skipped_checks": [],
        },
        "summary": {"passed": 1, "failed": 1},
    }
    report = gr.build_report(checkov_report, _fixture_check_to_themes(), FIXTURE_THEMES)
    as_json = gr.render_json(report)
    import json

    serialized = json.dumps(as_json)  # must not raise
    parsed = json.loads(serialized)
    assert parsed["frameworks"]["iso27001"]["passed"] == 1
    assert parsed["frameworks"]["iso27001"]["failed"] == 1
    assert parsed["frameworks"]["iso27001"]["compliance_pct"] == 50.0


def test_real_mapping_file_loads_and_every_theme_has_at_least_one_framework():
    from pathlib import Path

    check_to_themes, themes = gr.load_mapping(Path(gr.DEFAULT_MAPPING))
    assert len(themes) > 0
    for theme_key, theme in themes.items():
        assert theme["frameworks"], f"theme {theme_key} has no framework mappings"
        assert theme["checks"], f"theme {theme_key} has no checks"


def test_real_mapping_file_has_no_duplicate_check_assignment_within_a_theme():
    from pathlib import Path

    _, themes = gr.load_mapping(Path(gr.DEFAULT_MAPPING))
    for theme_key, theme in themes.items():
        checks = theme["checks"]
        assert len(checks) == len(set(checks)), f"duplicate check_id within theme {theme_key}"
