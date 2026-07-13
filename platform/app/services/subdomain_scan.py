"""Subdomain enumeration: subfinder (passive sources) + crt.sh (certificate
transparency logs). Both sources are passive - they query third-party data
sets rather than sending traffic to the target - so this step alone carries
none of the "did I just port-scan someone" risk that services/port_scan.py
does. The verification gate is still enforced here for defense in depth and
consistency: every function in this module that takes a Domain checks it.
"""

from __future__ import annotations

import json
import logging
import subprocess

import httpx

from app.config import get_settings
from app.models import Domain
from app.services.verification import require_verified

logger = logging.getLogger(__name__)


def _run_subfinder(domain_name: str, binary: str, timeout: int = 120) -> set[str]:
    """Shell out to subfinder in silent JSON-lines mode. Returns an empty set
    (rather than raising) if the binary isn't installed, so this service
    degrades to crt.sh-only instead of hard failing - useful in local dev
    where subfinder may not be present.
    """
    try:
        proc = subprocess.run(
            [binary, "-d", domain_name, "-silent", "-oJ"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        logger.info("subfinder binary '%s' not found - skipping active source", binary)
        return set()
    except subprocess.TimeoutExpired:
        logger.warning("subfinder timed out for %s", domain_name)
        return set()

    found: set[str] = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            host = record.get("host")
        except json.JSONDecodeError:
            host = line  # non-JSON silent mode fallback: one hostname per line
        if host:
            found.add(host.lower().rstrip("."))
    return found


def _query_crtsh(domain_name: str, client: httpx.Client) -> set[str]:
    """Certificate Transparency log lookup via crt.sh's public JSON endpoint."""
    response = client.get(
        "https://crt.sh/",
        params={"q": f"%.{domain_name}", "output": "json"},
        timeout=30,
    )
    response.raise_for_status()
    found: set[str] = set()
    for entry in response.json():
        name_value = entry.get("name_value", "")
        for host in name_value.split("\n"):
            host = host.strip().lower().lstrip("*.").rstrip(".")
            if host.endswith(domain_name):
                found.add(host)
    return found


def enumerate_subdomains(
    domain: Domain, http_client: httpx.Client | None = None
) -> dict:
    """Return {"subdomains": [...], "sources": {...}} for `domain`.

    Raises PermissionError if `domain` is not verified - see
    services/verification.py.
    """
    require_verified(domain)
    settings = get_settings()

    subfinder_hosts = _run_subfinder(domain.name, settings.subfinder_binary)

    owns_client = http_client is None
    client = http_client or httpx.Client()
    try:
        try:
            crtsh_hosts = _query_crtsh(domain.name, client)
        except httpx.HTTPError as exc:
            logger.warning("crt.sh lookup failed for %s: %s", domain.name, exc)
            crtsh_hosts = set()
    finally:
        if owns_client:
            client.close()

    all_hosts = sorted(subfinder_hosts | crtsh_hosts | {domain.name})
    return {
        "subdomains": all_hosts,
        "sources": {
            "subfinder": sorted(subfinder_hosts),
            "crtsh": sorted(crtsh_hosts),
        },
    }


def diff_subdomains(previous: list[str] | None, current: list[str]) -> dict:
    """Compare two subdomain scans. Used to decide whether an alert-worthy
    change happened (see services/alerting.py) - a brand-new subdomain
    appearing is the single highest-signal event this scan type produces
    (e.g. a forgotten staging environment, a shadow-IT SaaS CNAME, ...).
    """
    previous_set = set(previous or [])
    current_set = set(current)
    return {
        "added": sorted(current_set - previous_set),
        "removed": sorted(previous_set - current_set),
    }
