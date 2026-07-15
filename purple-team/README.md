# Purple Team Simulation (Brique 3)

A small Breach & Attack Simulation orchestrator: runs MITRE ATT&CK technique commands against an explicitly authorized lab target, asks a pluggable Detector whether the detection stack noticed, and reports per-technique and aggregate detection coverage.

Positioned deliberately as a **skill-demonstration module**, not a product feature to sell: commercial BAS tools (AttackIQ, SafeBreach) are a mature, competitive market. What's genuinely useful here is proving the methodology - orchestrator + technique library + pluggable detector + pass/fail coverage report - end to end, on real (if narrow) technique execution.

## The safety model

This is the one place in the repo where the "don't run this against something you don't control" principle from `platform/app/services/verification.py` (DNS TXT domain verification) gets adapted to a different shape of problem: there's no equivalent of "prove domain ownership via DNS" for an arbitrary lab host, so the gate here is simpler and stricter by default.

1. **Only techniques classified `safety: read_only` exist in `atomics/`.** See `atomics/README.md` for the curated list (7 MITRE discovery techniques - system info, processes, network config, services, files - all pure reconnaissance, nothing that creates, modifies, or deletes state). `tests/test_atomics_library.py` enforces this with an explicit disallowed-command-pattern check on every technique file, so a future addition that isn't actually read-only fails CI, not just code review.
2. **Targets are an explicit allowlist, not a hostname you can type on the CLI.** `lab-config.yaml` ships with exactly one entry: `localhost`, pre-confirmed - the only target this codebase can execute against without any external attestation, because it's the machine running the code. Any other host requires manually editing that file and setting `confirmed_own_lab: true` yourself; the schema defaults that field to `False`, so a copy-pasted new entry stays blocked. See `safety.py`.
3. **The gate is checked at the orchestrator's single entry point** (`orchestrator.run_all`), before any technique executes - not scattered as an assumption across call sites. Verified with a live CLI run against an unconfirmed host (not just a unit test): `python3 orchestrator.py --target some-random-host --lab-config /tmp/test.yaml` exits 1 with `Refusing to run techniques against 'some-random-host'...`.

## What was actually run

`reports/purple-team-report.{md,json}` is real output from `python3 orchestrator.py --target localhost --detector null`, executed in this development environment: **7/7 curated techniques ran successfully (exit code 0) against this machine**, and the `NullDetector` correctly reports 0% detection coverage - because no detection stack (Wazuh, GuardDuty, Suricata) is deployed anywhere in this project (see the root README: the landing zone is validated/scanned, not deployed to AWS). That's the honest result, not a bug: `report.py` explicitly distinguishes "0% because nothing is watching" from "0% because the detection stack watched and missed everything" so this report can't be misread as a detection-stack failure.

## Detectors

| Detector | Status | Backend |
|---|---|---|
| `NullDetector` | **Live-tested** (used to generate `reports/`) | None - always reports not-detected, with an explicit "not configured" reason |
| `WazuhDetector` | Real code, unit-tested against a mocked Wazuh indexer response shape | Queries `rule.mitre.id` in the `wazuh-alerts-*` OpenSearch index for a matching alert in the run's time window |
| `GuardDutyDetector` | Real code, unit-tested against a mocked `boto3` client | `guardduty:ListFindings`, with an explicit, intentionally small technique→finding-type map (`TECHNIQUE_TO_FINDING_TYPE_PREFIX` in `detectors/guardduty.py`) - AWS does not tag GuardDuty findings with MITRE technique IDs the way Wazuh's ruleset does, so this is best-effort correlation, documented as such rather than presented as exact |

Neither Wazuh nor GuardDuty is exercised against a live backend in this repo, for the same reason nothing else here is deployed: there's no running detection stack to test against yet. If the landing zone in this repo were deployed with GuardDuty enabled, `--detector guardduty --guardduty-detector-id <id>` would need CLI wiring added to `orchestrator.build_detector()` (currently raises `NotImplementedError` with a pointer to construct the detector programmatically) - a deliberately small gap, not an oversight, since there's nothing to point it at yet.

## Running it

```bash
pip install -r requirements.txt

# See what would run, without running anything
python3 orchestrator.py --dry-run

# Actually run the curated safe set against this machine
python3 orchestrator.py --target localhost --detector null \
  --output-md reports/purple-team-report.md \
  --output-json reports/purple-team-report.json

# Restrict to one technique
python3 orchestrator.py --target localhost --technique T1082
```

## Testing

```bash
pytest tests/ -v
```

27 tests: the safety gate (localhost always allowed, unconfirmed remote hosts always refused, a missing `confirmed_own_lab` key defaults to `False` not `True`), the atomics library (every technique is read-only by an explicit, auditable substring check), the orchestrator (dry-run vs. real execution, unknown/unconfirmed target handling), both detectors (mocked HTTP/boto3), and report rendering.

## Extending the technique library

Before adding a technique beyond pure discovery/recon:

1. Does it create, modify, or delete anything (a file, a registry key, a process, a scheduled task)? If yes, it needs a `test.cleanup` command and a safety classification other than `read_only` - and `orchestrator.py` currently has no execution path for anything other than `read_only` techniques. That's intentional, not a missing feature to casually patch around; adding state-modifying techniques means also adding a cleanup-verification step and rethinking what "safe to run in CI/against localhost by default" means.
2. Is the technique ID and command actually sourced from (or consistent with) Atomic Red Team's public library or another named reference, not invented? Cite it in the YAML's `description`.
3. Does `tests/test_atomics_library.py`'s `DISALLOWED_SUBSTRINGS` check need a new entry to keep catching accidental state changes in future techniques?

## What this is not

- **Not a substitute for Atomic Red Team's actual library** (hundreds of techniques, PowerShell/registry-heavy on Windows, many requiring cleanup steps). This is a small, safety-first Linux/macOS discovery subset chosen so it's honestly safe to execute in a portfolio/CI context.
- **Not a live-tested integration with any detection stack.** Wazuh and GuardDuty support is real code with real tests against mocked responses, not a demonstrated live pipeline - see "What was actually run" above for exactly what has and hasn't been exercised.
- **Not penetration testing.** No exploitation, no privilege escalation, no lateral movement - purely observational reconnaissance commands, and only ever against a target this codebase can verify authorization for (see "The safety model"). Real offensive testing remains a separately-demonstrated skill (lab writeups, certifications), consistent with the same boundary drawn in `platform/README.md`'s roadmap section.
