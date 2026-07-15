from orchestrator import TechniqueResult
from report import render_json, render_markdown


def _result(technique_id="T1082", executed=True, detected=False, exit_code=0):
    return TechniqueResult(
        technique_id=technique_id,
        display_name="Fake",
        tactic="discovery",
        command="echo hi",
        executed=executed,
        exit_code=exit_code,
        detected=detected,
        detector_name="null",
        evidence="no detector configured",
    )


def test_render_markdown_computes_coverage_percentage():
    results = [_result(detected=True), _result("T1033", detected=False)]
    markdown = render_markdown(results, target="localhost", detector_name="null")
    assert "1/2 (50.0%)" in markdown


def test_render_markdown_flags_zero_detection_across_the_board():
    results = [_result(detected=False), _result("T1033", detected=False)]
    markdown = render_markdown(results, target="localhost", detector_name="null")
    assert "Every executed technique went undetected" in markdown


def test_render_markdown_dry_run_has_no_coverage_line():
    results = [
        TechniqueResult(
            technique_id="T1082",
            display_name="Fake",
            tactic="discovery",
            command="echo hi",
            executed=False,
            exit_code=None,
            detected=None,
            detector_name=None,
            evidence=None,
            skip_reason="dry-run",
        )
    ]
    markdown = render_markdown(results, target="localhost", detector_name="null", dry_run=True)
    assert "Dry run" in markdown
    assert "Detection coverage" not in markdown


def test_render_json_summary_counts_match():
    results = [_result(detected=True), _result("T1033", detected=False), _result("T1057", executed=False, detected=None)]
    payload = render_json(results)
    assert payload["summary"]["total"] == 3
    assert payload["summary"]["executed"] == 2
    assert payload["summary"]["detected"] == 1
