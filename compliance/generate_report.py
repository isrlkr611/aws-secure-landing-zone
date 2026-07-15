#!/usr/bin/env python3
"""Cross-reference real Checkov results against compliance/mapping_norms.yaml
and produce a per-framework compliance report.

This is deliberately NOT a general-purpose GRC tool - it maps exactly the
check IDs that show up when scanning this repo's terraform/ tree (see the
header comment in mapping_norms.yaml) to specific ISO 27001 / PCI-DSS /
NIS2 / SOC 2 clauses, and is honest about what it doesn't cover: any
check_id encountered that isn't in the mapping file is reported as
"unmapped", not silently dropped, and every framework's compliance
percentage is computed only from checks that were actually evaluated
against this specific infrastructure - never inferred or assumed.

Usage:
    python3 generate_report.py [--checkov-json PATH] [--mapping PATH]
                                [--output-md PATH] [--output-json PATH]

If --checkov-json is omitted, checkov is run live against terraform/ at the
repo root (requires `checkov` on PATH).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MAPPING = Path(__file__).resolve().parent / "mapping_norms.yaml"


@dataclass
class FrameworkStats:
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    failed_items: list[dict] = field(default_factory=list)
    skipped_items: list[dict] = field(default_factory=list)

    @property
    def evaluated(self) -> int:
        return self.passed + self.failed

    @property
    def compliance_pct(self) -> float | None:
        if self.evaluated == 0:
            return None
        return round(100 * self.passed / self.evaluated, 1)


def run_checkov(directory: str = "terraform/") -> dict:
    """Run checkov against `directory` and return its parsed JSON report.

    Deliberately does NOT pass --quiet: in checkov 3.x, --quiet also strips
    passed_checks from the JSON output (it's meant to declutter CLI text,
    but it has this side effect on machine-readable output too), which
    would silently make every framework's compliance percentage wrong.
    """
    proc = subprocess.run(
        ["checkov", "-d", directory, "--output", "json"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    if not proc.stdout.strip():
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError("checkov produced no output - is it installed and on PATH?")
    return json.loads(proc.stdout)


def load_mapping(path: Path) -> tuple[dict[str, list[str]], dict[str, dict]]:
    """Return (check_id -> [theme_key, ...], theme_key -> theme_definition)."""
    raw = yaml.safe_load(path.read_text())
    themes = raw["themes"]

    check_to_themes: dict[str, list[str]] = defaultdict(list)
    for theme_key, theme in themes.items():
        for check_id in theme["checks"]:
            check_to_themes[check_id].append(theme_key)

    return dict(check_to_themes), themes


def build_report(checkov_report: dict, check_to_themes: dict, themes: dict) -> dict:
    framework_stats: dict[str, FrameworkStats] = defaultdict(FrameworkStats)
    theme_stats: dict[str, FrameworkStats] = defaultdict(FrameworkStats)
    unmapped_checks: dict[str, int] = defaultdict(int)

    results = checkov_report.get("results", {})

    def frameworks_for(check_id: str) -> set[str]:
        fw = set()
        for theme_key in check_to_themes.get(check_id, []):
            fw.update(themes[theme_key]["frameworks"].keys())
        return fw

    def record(check_id: str, item: dict, bucket: str) -> None:
        theme_keys = check_to_themes.get(check_id)
        if not theme_keys:
            unmapped_checks[check_id] += 1
            return

        for theme_key in theme_keys:
            stats = theme_stats[theme_key]
            setattr(stats, bucket, getattr(stats, bucket) + 1)
            if bucket == "failed":
                stats.failed_items.append(item)
            elif bucket == "skipped":
                stats.skipped_items.append(item)

        for fw in frameworks_for(check_id):
            stats = framework_stats[fw]
            setattr(stats, bucket, getattr(stats, bucket) + 1)
            if bucket == "failed":
                stats.failed_items.append(item)
            elif bucket == "skipped":
                stats.skipped_items.append(item)

    for entry in results.get("passed_checks", []):
        record(entry["check_id"], entry, "passed")

    for entry in results.get("failed_checks", []):
        record(entry["check_id"], entry, "failed")

    for entry in results.get("skipped_checks", []):
        record(entry["check_id"], entry, "skipped")

    return {
        "framework_stats": framework_stats,
        "theme_stats": theme_stats,
        "unmapped_checks": dict(unmapped_checks),
        "totals": checkov_report.get("summary", {}),
    }


FRAMEWORK_NAMES = {
    "iso27001": "ISO/IEC 27001:2022 (Annex A)",
    "pci_dss": "PCI-DSS v4.0",
    "nis2": "NIS2 Directive (Art. 21(2))",
    "soc2": "SOC 2 (Trust Services Criteria)",
}


def render_markdown(report: dict, themes: dict) -> str:
    lines = ["# Compliance Mapping Report", ""]
    lines.append(
        "Generated from a real `checkov -d terraform/` scan of this repo's infrastructure "
        "code, cross-referenced against `compliance/mapping_norms.yaml`. Not a substitute "
        "for a formal audit - see `compliance/README.md` for methodology and limitations."
    )
    lines.append("")

    totals = report["totals"]
    lines.append(
        f"**Underlying scan**: {totals.get('passed', 0)} passed, "
        f"{totals.get('failed', 0)} failed, {totals.get('skipped', 0)} skipped "
        f"({totals.get('resource_count', '?')} resources, Checkov {totals.get('checkov_version', '?')})."
    )
    lines.append("")

    lines.append("## Compliance by framework")
    lines.append("")
    lines.append("| Framework | Compliance | Evaluated | Passed | Failed | Documented exceptions |")
    lines.append("|---|---|---|---|---|---|")
    for fw_key in sorted(report["framework_stats"], key=lambda k: FRAMEWORK_NAMES.get(k, k)):
        stats: FrameworkStats = report["framework_stats"][fw_key]
        pct = f"{stats.compliance_pct}%" if stats.compliance_pct is not None else "N/A"
        lines.append(
            f"| {FRAMEWORK_NAMES.get(fw_key, fw_key)} | **{pct}** | {stats.evaluated} | "
            f"{stats.passed} | {stats.failed} | {stats.skipped} |"
        )
    lines.append("")
    lines.append(
        "\"Documented exceptions\" are checks Checkov flagged that were reviewed and "
        "explicitly accepted in the code (`checkov:skip=...` with an inline justification "
        "- see `docs/architecture.md` \"Security Choices\"). They are **not** counted "
        "toward the compliance percentage above; an auditor would need to review each one "
        "as a compensating control, which is exactly why they're broken out separately "
        "rather than folded into \"passed\"."
    )
    lines.append("")

    if any(s.failed for s in report["framework_stats"].values()):
        lines.append("## Gaps (failed checks)")
        lines.append("")
        for fw_key, stats in report["framework_stats"].items():
            if not stats.failed_items:
                continue
            lines.append(f"### {FRAMEWORK_NAMES.get(fw_key, fw_key)}")
            for item in stats.failed_items:
                lines.append(f"- `{item['check_id']}` ({item['resource']}): {item['check_name']}")
            lines.append("")

    lines.append("## Documented exceptions requiring compensating-control review")
    lines.append("")
    seen = set()
    for stats in report["framework_stats"].values():
        for item in stats.skipped_items:
            key = (item["check_id"], item["resource"])
            if key in seen:
                continue
            seen.add(key)
            comment = (item.get("check_result", {}).get("suppress_comment") or "").strip()
            lines.append(f"- `{item['check_id']}` ({item['resource']}): {comment}")
    lines.append("")

    lines.append("## Coverage by control theme")
    lines.append("")
    for theme_key, stats in report["theme_stats"].items():
        theme = themes[theme_key]
        pct = f"{stats.compliance_pct}%" if stats.compliance_pct is not None else "N/A"
        fw_list = ", ".join(FRAMEWORK_NAMES.get(f, f) for f in theme["frameworks"])
        lines.append(f"- **{theme['title']}** - {pct} ({stats.passed}/{stats.evaluated}), skipped: {stats.skipped}")
        lines.append(f"  Maps to: {fw_list}")
    lines.append("")

    if report["unmapped_checks"]:
        lines.append("## Unmapped checks")
        lines.append("")
        lines.append(
            "Checks Checkov evaluated that are not yet covered by `mapping_norms.yaml` - "
            "listed here rather than silently excluded from this report:"
        )
        lines.append("")
        for check_id, count in sorted(report["unmapped_checks"].items()):
            lines.append(f"- `{check_id}` ({count} occurrence(s))")
        lines.append("")

    return "\n".join(lines)


def render_json(report: dict) -> dict:
    def stats_to_dict(stats: FrameworkStats) -> dict:
        return {
            "passed": stats.passed,
            "failed": stats.failed,
            "skipped": stats.skipped,
            "evaluated": stats.evaluated,
            "compliance_pct": stats.compliance_pct,
        }

    return {
        "totals": report["totals"],
        "frameworks": {k: stats_to_dict(v) for k, v in report["framework_stats"].items()},
        "themes": {k: stats_to_dict(v) for k, v in report["theme_stats"].items()},
        "unmapped_checks": report["unmapped_checks"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkov-json", type=Path, default=None)
    parser.add_argument("--mapping", type=Path, default=DEFAULT_MAPPING)
    parser.add_argument("--output-md", type=Path, default=None)
    parser.add_argument("--output-json", type=Path, default=None)
    args = parser.parse_args()

    checkov_report = (
        json.loads(args.checkov_json.read_text()) if args.checkov_json else run_checkov()
    )
    check_to_themes, themes = load_mapping(args.mapping)
    report = build_report(checkov_report, check_to_themes, themes)

    markdown = render_markdown(report, themes)
    if args.output_md:
        args.output_md.write_text(markdown)
        print(f"Wrote {args.output_md}", file=sys.stderr)
    else:
        print(markdown)

    if args.output_json:
        args.output_json.write_text(json.dumps(render_json(report), indent=2))
        print(f"Wrote {args.output_json}", file=sys.stderr)


if __name__ == "__main__":
    main()
