"""
Domain ownership verification via DNS TXT record challenge.

--- WHY THIS FILE EXISTS AND MUST NOT BE BYPASSED --------------------------
Scanning a domain (subdomain enumeration, port scanning, service
fingerprinting) without authorization is a criminal offense in most
jurisdictions this platform could be used from - in France specifically,
unauthorized access/scanning of an automated data processing system is
punishable under Code pénal Art. 323-1. "The user typed a domain into a
form" is not authorization; proof of control over the domain's DNS is the
closest a fully automated SaaS product can get to real authorization
without a manual contract review per domain, and it is the same mechanism
Google Search Console, Bing Webmaster Tools, and every legitimate ASM
vendor use.

Every scan-triggering code path (see services/subdomain_scan.py,
services/port_scan.py, services/tls_check.py) MUST check
`domain.is_verified` before doing anything that touches the target's
network or infrastructure. This module only flips that flag - nothing else
in the codebase is allowed to.
---------------------------------------------------------------------------
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import dns.exception
import dns.resolver

from app.models import Domain

logger = logging.getLogger(__name__)


@dataclass
class VerificationOutcome:
    verified: bool
    detail: str


def _lookup_txt_records(domain_name: str, resolver: dns.resolver.Resolver | None = None) -> list[str]:
    """Return every TXT record value published for `domain_name`, decoded to str.

    Raises dns.exception.DNSException subclasses on lookup failure - callers
    decide how to translate that into a user-facing message.
    """
    resolver = resolver or dns.resolver.Resolver()
    answer = resolver.resolve(domain_name, "TXT")
    values: list[str] = []
    for record in answer:
        # TXT records can be split into multiple <character-string> chunks;
        # dnspython exposes them as record.strings (bytes each).
        raw = b"".join(record.strings) if hasattr(record, "strings") else bytes(record)
        values.append(raw.decode("utf-8", errors="replace"))
    return values


def verify_domain_ownership(
    domain: Domain, resolver: dns.resolver.Resolver | None = None
) -> VerificationOutcome:
    """Check whether `domain`'s expected TXT challenge value is published.

    Does NOT mutate `domain` - the caller (the /domains/{id}/verify route)
    is responsible for persisting verified_at so this function stays a pure
    "check the world" operation that's trivial to unit test.
    """
    expected = domain.verification_dns_record

    try:
        published = _lookup_txt_records(domain.name, resolver=resolver)
    except dns.resolver.NXDOMAIN:
        return VerificationOutcome(False, f"Domain '{domain.name}' does not exist (NXDOMAIN).")
    except dns.resolver.NoAnswer:
        return VerificationOutcome(
            False,
            f"No TXT records found for '{domain.name}'. Publish the required TXT record and retry.",
        )
    except dns.exception.Timeout:
        return VerificationOutcome(False, "DNS lookup timed out. Try again shortly.")
    except dns.exception.DNSException as exc:
        logger.warning("DNS verification lookup failed for %s: %s", domain.name, exc)
        return VerificationOutcome(False, f"DNS lookup failed: {exc}")

    if expected in published:
        return VerificationOutcome(True, "Ownership verified via DNS TXT record.")

    return VerificationOutcome(
        False,
        f"Expected TXT record '{expected}' not found among {len(published)} TXT record(s) "
        f"for '{domain.name}'. DNS changes can take time to propagate.",
    )


def mark_verified(domain: Domain) -> None:
    """The only place in the codebase allowed to set verified_at."""
    domain.verified_at = datetime.now(timezone.utc)


def require_verified(domain: Domain) -> None:
    """Hard gate used by every scan service. Raises if the domain isn't verified.

    This is intentionally redundant with the same check likely already done
    at the API layer - a service function should never trust its caller to
    have remembered the legal gate, because the cost of that assumption
    being wrong is an actual unauthorized scan.
    """
    if not domain.is_verified:
        raise PermissionError(
            f"Domain '{domain.name}' is not verified. Refusing to scan an "
            f"unverified domain (see app/services/verification.py)."
        )
