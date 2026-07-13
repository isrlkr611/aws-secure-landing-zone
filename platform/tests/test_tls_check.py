from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.services import tls_check


def _fake_not_after(days_from_now: int) -> str:
    expiry = datetime.now(timezone.utc) + timedelta(days=days_from_now)
    return expiry.strftime(tls_check._CERT_DATE_FORMAT).replace("UTC", "GMT")


def test_get_certificate_expiry_parses_cert_date():
    not_after_str = "Jan  1 00:00:00 2030 GMT"
    fake_cert = {"notAfter": not_after_str}

    fake_tls_sock = MagicMock()
    fake_tls_sock.getpeercert.return_value = fake_cert
    fake_tls_sock.__enter__.return_value = fake_tls_sock
    fake_tls_sock.__exit__.return_value = False

    fake_context = MagicMock()
    fake_context.wrap_socket.return_value = fake_tls_sock

    fake_raw_sock = MagicMock()

    with patch.object(tls_check.ssl, "create_default_context", return_value=fake_context), patch.object(
        tls_check.socket, "create_connection"
    ) as mock_create_connection:
        mock_create_connection.return_value.__enter__.return_value = fake_raw_sock
        expiry = tls_check._get_certificate_expiry("example.com")

    assert expiry.year == 2030
    assert expiry.month == 1


def test_check_certificate_flags_soon_expiring_cert(verified_domain):
    soon = datetime.now(timezone.utc) + timedelta(days=10)
    with patch.object(tls_check, "_get_certificate_expiry", return_value=soon):
        result = tls_check.check_certificate(verified_domain)

    assert result["expiring_soon"] is True
    assert result["days_remaining"] in (9, 10)


def test_check_certificate_does_not_flag_healthy_cert(verified_domain):
    far_future = datetime.now(timezone.utc) + timedelta(days=200)
    with patch.object(tls_check, "_get_certificate_expiry", return_value=far_future):
        result = tls_check.check_certificate(verified_domain)

    assert result["expiring_soon"] is False


def test_check_certificate_enforces_verification_gate(unverified_domain):
    with pytest.raises(PermissionError):
        tls_check.check_certificate(unverified_domain)
