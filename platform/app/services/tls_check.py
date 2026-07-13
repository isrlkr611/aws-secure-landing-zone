"""TLS certificate expiry tracking.

A plain TLS handshake to read the certificate presented is not considered
"scanning" in the same sense as a port sweep - it's what every browser
does on every HTTPS visit - but the verification gate is still applied for
consistency and because a hostname the caller doesn't control could belong
to someone who'd rather not be probed at all, automated or not.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from app.models import Domain
from app.services.verification import require_verified

_CERT_DATE_FORMAT = "%b %d %H:%M:%S %Y %Z"


def _get_certificate_expiry(hostname: str, port: int = 443, timeout: float = 10.0) -> datetime:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            cert = tls_sock.getpeercert()
    not_after = cert["notAfter"]
    return datetime.strptime(not_after, _CERT_DATE_FORMAT).replace(tzinfo=timezone.utc)


def check_certificate(domain: Domain, port: int = 443) -> dict:
    require_verified(domain)

    expires_at = _get_certificate_expiry(domain.name, port=port)
    days_remaining = (expires_at - datetime.now(timezone.utc)).days

    return {
        "hostname": domain.name,
        "port": port,
        "expires_at": expires_at.isoformat(),
        "days_remaining": days_remaining,
        "expiring_soon": days_remaining <= 30,
    }
