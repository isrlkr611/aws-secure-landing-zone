"""Credential leak detection via the HaveIBeenPwned API.

Design note: HIBP's `/breacheddomain/{domain}` endpoint (bulk breach search
for every account at a domain) requires the domain to *also* be verified
directly with HIBP, on top of our own DNS TXT verification - that's a
separate, paid, manual process on their end and out of scope for this MVP.
Instead this service checks specific email addresses one at a time via
`/breachedaccount/{email}`, which only requires our API key. The caller
(the /domains/{id}/scan route, or a future "watched addresses" feature)
supplies which addresses are in scope - this module never invents or
guesses addresses to check.
"""

from __future__ import annotations

import logging

import httpx

from app.config import get_settings
from app.models import Domain
from app.services.verification import require_verified

logger = logging.getLogger(__name__)


class HIBPNotConfigured(RuntimeError):
    pass


def _check_single_email(email: str, client: httpx.Client, api_key: str, base_url: str) -> list[dict]:
    response = client.get(
        f"{base_url}/breachedaccount/{email}",
        params={"truncateResponse": "false"},
        headers={"hibp-api-key": api_key, "user-agent": "attack-surface-monitor"},
        timeout=15,
    )
    if response.status_code == 404:
        return []  # no breaches found - HIBP's documented "clean" response
    response.raise_for_status()
    return response.json()


def check_leaked_credentials(
    domain: Domain, emails: list[str], http_client: httpx.Client | None = None
) -> dict:
    """Check `emails` (expected to be addresses @domain.name, but not
    enforced here) against HIBP. Raises PermissionError if the domain
    isn't verified, HIBPNotConfigured if no API key is set.
    """
    require_verified(domain)
    settings = get_settings()

    if not settings.hibp_api_key:
        raise HIBPNotConfigured("HIBP_API_KEY is not configured - leak scanning is disabled.")

    owns_client = http_client is None
    client = http_client or httpx.Client()
    results: dict[str, list[dict]] = {}
    try:
        for email in emails:
            try:
                results[email] = _check_single_email(
                    email, client, settings.hibp_api_key, settings.hibp_base_url
                )
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    logger.warning("HIBP rate limit hit while checking %s", email)
                    results[email] = []
                else:
                    raise
    finally:
        if owns_client:
            client.close()

    breached = {email: breaches for email, breaches in results.items() if breaches}
    return {"checked": list(results.keys()), "breached": breached}
