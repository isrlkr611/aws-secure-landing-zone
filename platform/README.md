# Attack Surface Monitor

The workload this repo's [Secure Landing Zone](../README.md) is designed to host: continuous external attack-surface monitoring for domains a user proves they own. This is the MVP slice ("Brique 1") of a larger planned product - see [Roadmap](#roadmap) for what's deliberately not built yet.

**Status: code + tests only, not deployed, no live scans executed against any external target from this development environment.** Every scan-capable function is covered by tests that mock the network/subprocess call it would otherwise make - see [Testing](#testing).

## The legal safeguard, and why it's not optional

Scanning a domain (subdomain enumeration, port scanning, service fingerprinting) without authorization is a criminal offense in most jurisdictions - in France specifically, unauthorized access to or scanning of an automated data processing system is punishable under **Code pénal Art. 323-1**. "A user typed a domain into a form" is not authorization.

This platform requires DNS TXT ownership verification - the same mechanism Google Search Console and Bing Webmaster Tools use - before any scan of a domain can run:

1. `POST /domains` registers a domain and returns a unique TXT record value to publish.
2. The user adds that TXT record to their domain's DNS.
3. `POST /domains/{id}/verify` performs a live DNS lookup and only then sets `verified_at`.
4. Every scan service (`app/services/subdomain_scan.py`, `port_scan.py`, `tls_check.py`, `leak_check.py`) independently calls `require_verified(domain)` at its own entry point and raises `PermissionError` if it's missing - **not** trusting the API layer to have already checked. See `app/services/verification.py` for the full rationale, and `tests/test_legal_gate_enforced_everywhere.py` for the test suite that exists specifically to prove every scan path enforces this, individually.

An unverified-domain scan attempt is not silently dropped either - it's recorded as a `ScanResult` with `status=blocked_unverified`, so the attempt itself is auditable.

## Architecture

```
platform/
├── app/
│   ├── main.py              FastAPI app, router wiring
│   ├── config.py             Settings (env-driven, see .env.example)
│   ├── models.py              SQLAlchemy: User, Domain, ScanResult, Finding
│   ├── schemas.py              Pydantic request/response models
│   ├── security.py              API key issuance/verification
│   ├── routers/                  auth.py, domains.py, scans.py, leaks.py
│   ├── services/                   one module per scan type + verification.py + alerting.py
│   └── tasks/scheduler.py            periodic re-scan (local dev: APScheduler; prod: k8s CronJob calls this)
├── tests/                     45 tests, all offline (mocked subprocess/HTTP/DNS)
├── k8s/                        Deployment, CronJob, NetworkPolicy, ExternalSecret
├── Dockerfile                   multi-stage, non-root, nmap + subfinder
└── requirements*.txt
```

Each domain a user registers gets its own verification token and independent `verified_at` state - there is no way to scan domain B by virtue of having verified domain A.

## What each scan type actually does

| Scan | Source | Traffic sent to target? |
|---|---|---|
| Subdomains | `subfinder` (passive OSINT) + crt.sh (certificate transparency logs) | No - both are third-party data lookups, not probes of the target itself |
| Ports/services | `nmap -sT` (TCP connect scan) against a fixed, conservative port list (`SCAN_COMMON_PORTS`), rate-capped at `NMAP_MAX_RATE` (default 100 pkt/s) | Yes - this is the one scan type that touches the target's infrastructure directly |
| TLS certificate | Direct TLS handshake, reads the presented certificate's expiry | Yes, but equivalent to any browser visit |
| Leaked credentials | HaveIBeenPwned `/breachedaccount/{email}` API, for caller-supplied addresses | No - queries a third-party breach database, not the target |

The port scanner uses `-sT` (TCP connect) rather than a raw-socket SYN scan specifically so the container needs no elevated capabilities - see the Dockerfile and `k8s/deployment.yaml`, both of which run as a fully unprivileged, non-root user with every Linux capability dropped, consistent with the `restricted` Pod Security Standard enforced on the `attack-surface-monitor` namespace (see `k8s/namespace.yaml`).

## Running locally

```bash
cd platform
python3 -m venv .venv && source .venv/bin/activate   # or: pip install --break-system-packages -r requirements-dev.txt
pip install -r requirements-dev.txt
cp .env.example .env

uvicorn app.main:app --reload
# http://localhost:8000/docs for interactive API docs
```

`subfinder` and `nmap` are optional for local dev: `subdomain_scan.py` degrades gracefully to crt.sh-only if the `subfinder` binary isn't found, and `port_scan.py` raises a clear `NmapNotAvailable` error (deliberately loud, not silently skipped - a missing scanner should never look like "no open ports found").

## Testing

```bash
cd platform
pytest tests/ -v
```

45 tests, 0 network calls, 0 subprocess calls to real `nmap`/`subfinder` binaries - every external dependency is mocked (`unittest.mock` for subprocess/DNS/TLS, `respx` for HTTP). This was a deliberate scope decision for this development environment: running `masscan`/`nmap` against arbitrary targets could itself look like an unauthorized scan, so the test suite proves the *code* is correct without ever touching a live target. `tests/test_legal_gate_enforced_everywhere.py` is the file to read first - it's the regression suite for the one thing in this codebase that must never regress.

## Deploying (`k8s/`)

Designed to run as a workload on the EKS cluster provisioned by [`terraform/`](../terraform/) at the repo root:

- `namespace.yaml` - same `restricted` Pod Security Standard as the rest of the landing zone.
- `deployment.yaml` - the API, 2 replicas, IRSA-annotated service account, all container hardening flags set (`runAsNonRoot`, `readOnlyRootFilesystem`, `capabilities.drop: [ALL]`).
- `cronjob-scan.yaml` - daily re-scan of every verified domain, same hardening, separate `ServiceAccount`.
- `external-secret.yaml` - reuses the `ClusterSecretStore` defined in [`kubernetes/external-secrets/`](../kubernetes/external-secrets/) at the repo root; every credential (DB URL, HIBP key, SMTP, Slack webhook) comes from AWS Secrets Manager, never a plaintext manifest.
- `network-policy.yaml` - deny-by-default, with one deliberate, documented exception: `allow-scan-egress` permits broad outbound traffic because port-scanning arbitrary (verified) target ports is this namespace's entire purpose - see the comment in that file for why a fixed allow-list can't work here the way it does for the landing zone's own internal app tiers, and why the actual authorization control lives in application code (`require_verified`) rather than the network layer.

## Container image scan results

Built and smoke-tested locally (`docker build`, then verified `/healthz`, non-root execution, and both `nmap`/`subfinder` working inside the container), then scanned with Trivy (`--ignore-unfixed`, matching the CI policy in `.github/workflows/platform-ci.yml`): **0 fixable Debian OS package findings**; **29 findings (28 HIGH, 1 CRITICAL) in the `subfinder` binary's embedded Go dependencies** (`golang.org/x/crypto` and Go stdlib), all with fixes available in a newer Go build than the upstream `subfinder` v2.14.0 release ships with. Full output: [`docs/scan-results/trivy-image-scan.txt`](docs/scan-results/trivy-image-scan.txt).

This is an accepted, monitored risk rather than a blocker: `subfinder` is invoked as a subprocess for passive OSINT lookups only (see table above - it never accepts inbound connections, and the container it runs in has no network capabilities beyond what `network-policy.yaml` explicitly allows), the container runs fully unprivileged, and the fix is mechanical (bump the pinned `SUBFINDER_VERSION` build arg once upstream publishes a build against a patched Go toolchain) rather than requiring any code change here. Each CVE is listed individually, by ID, in [`.trivyignore`](.trivyignore) - CI (`platform-ci.yml`) still fails the build on any CVE not already in that file, so this exception is scoped and self-expiring, not a blanket suppression.

## What's simplified for the MVP

Being explicit about this is more useful than pretending otherwise:

- **Scans run synchronously on the request path** (`POST /domains/{id}/scan/{type}` blocks until the scan finishes). Production would queue this and poll/webhook for the result instead, so a slow `nmap` run doesn't hold an HTTP connection open - `k8s/cronjob-scan.yaml` already runs scans out-of-band for the *scheduled* case, this gap is specifically the ad-hoc/on-demand trigger.
- **Schema managed with `create_all()`**, not Alembic migrations - fine for a fresh SQLite/dev database, not for evolving a production schema without downtime.
- **No multi-tenant rate limiting or plan/quota enforcement** - the "Stripe billing, free vs. paid quota" piece from the product brief is not implemented; this MVP is single-tier.
- **HIBP domain-wide breach search is not used** - `/breacheddomain/{domain}` requires separately verifying the domain with HIBP itself (a manual, paid process on their end); this MVP checks specific caller-supplied email addresses via `/breachedaccount/{email}` instead, which only needs our own API key.
- **No frontend** - this is the API only. `/docs` (FastAPI's auto-generated Swagger UI) is the only UI that exists today.

## Roadmap

Per the product brief this MVP is the first slice of:

1. **Brique 1 (this)**: attack surface monitoring - subdomains, ports, TLS, leaked credentials, gated by DNS TXT verification.
2. **Brique 2 ([`compliance/`](../compliance/), started)**: compliance mapping against ISO 27001 / PCI-DSS / NIS2 / SOC 2. Currently wired to the Terraform/Checkov side only (the "cloud posture scanner" half of the brief) - **not yet** to this platform's own findings (`new_open_port`, `cert_expiring`, `leaked_credentials` in `app/models.py`). Extending it means adding those finding categories to `compliance/mapping_norms.yaml` the same way the 61 Checkov check IDs are mapped today, and pointing `compliance/generate_report.py` at this platform's `Finding` table in addition to a checkov JSON report.
3. **Brique 3 ([`purple-team/`](../purple-team/), started)**: purple-team simulation - Atomic Red Team-style techniques run against the operator's own lab only (never a customer's infrastructure without a separate contract), verifying whether the detection stack (GuardDuty/Sentinel, Wazuh/Suricata) actually alerts. Currently a curated 7-technique read-only discovery set, live-executed against localhost with a `NullDetector`; Wazuh/GuardDuty detector integrations are real, unit-tested code not yet exercised against a live detection stack (none is deployed - see root README status).

Explicitly out of scope for this platform, permanently: penetration testing as a product feature. It requires a formal per-engagement authorization contract and manual exploitation a SaaS product structurally can't provide safely - kept as a separately demonstrated skill (lab writeups, certifications) rather than something this codebase claims to automate.
