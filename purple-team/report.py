"""Renders TechniqueResult lists (see orchestrator.py) into a Markdown
coverage report and a JSON summary - same "committed, real output, not a
mockup" pattern as compliance/generate_report.py.
"""

from __future__ import annotations

from dataclasses import asdict


def render_markdown(results: list, target: str, detector_name: str, dry_run: bool = False) -> str:
    lines = ["# Purple Team Detection Coverage Report", ""]

    if dry_run:
        lines.append(f"**Dry run** against target `{target}` - no commands executed, no detector queried.")
    else:
        lines.append(f"Target: `{target}` · Detector: `{detector_name}`")
    lines.append("")

    executed = [r for r in results if r.executed]
    detected = [r for r in executed if r.detected]

    if executed:
        coverage_pct = round(100 * len(detected) / len(executed), 1) if executed else None
        lines.append(f"**Detection coverage: {len(detected)}/{len(executed)} ({coverage_pct}%)**")
        lines.append("")

    lines.append("| Technique | Tactic | Executed | Exit code | Detected | Evidence |")
    lines.append("|---|---|---|---|---|---|")
    for r in results:
        executed_str = "yes" if r.executed else f"no ({r.skip_reason})"
        detected_str = "—" if r.detected is None else ("✅ yes" if r.detected else "❌ no")
        evidence = (r.evidence or "").replace("|", "\\|")
        lines.append(
            f"| `{r.technique_id}` {r.display_name} | {r.tactic} | {executed_str} | "
            f"{r.exit_code if r.exit_code is not None else '—'} | {detected_str} | {evidence} |"
        )
    lines.append("")

    if executed and not detected:
        lines.append(
            "**Every executed technique went undetected.** If a detection stack "
            "(Wazuh, GuardDuty) is expected to be watching this target, this is "
            "the finding that matters - it means either the stack isn't deployed, "
            "isn't tuned for these technique IDs, or the alert pipeline has a gap. "
            "If no detection stack is deployed at all (the current state of the "
            "landing zone in this repo - see docs/architecture.md), this is the "
            "expected, honest result, not a failure of this tool."
        )
        lines.append("")

    return "\n".join(lines)


def render_json(results: list) -> dict:
    return {
        "results": [asdict(r) for r in results],
        "summary": {
            "total": len(results),
            "executed": sum(1 for r in results if r.executed),
            "detected": sum(1 for r in results if r.detected),
        },
    }
