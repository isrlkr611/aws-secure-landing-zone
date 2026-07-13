"""This file exists to answer one question with certainty, not just hope:
does EVERY scan-capable service function actually refuse to run against an
unverified domain? Each test below calls the real service function (not a
mock of the gate itself) against `unverified_domain` and asserts it raises
PermissionError before doing anything network-related. If a future service
is added and someone forgets to call require_verified() at its entry
point, a test should be added here for it too - this file is the
"legal safeguard" regression suite.
"""

import pytest

from app.services import port_scan, subdomain_scan, tls_check
from app.services.leak_check import check_leaked_credentials


def test_subdomain_scan_refuses_unverified_domain(unverified_domain):
    with pytest.raises(PermissionError):
        subdomain_scan.enumerate_subdomains(unverified_domain)


def test_port_scan_refuses_unverified_domain(unverified_domain):
    with pytest.raises(PermissionError):
        port_scan.scan_ports(unverified_domain)


def test_tls_check_refuses_unverified_domain(unverified_domain):
    with pytest.raises(PermissionError):
        tls_check.check_certificate(unverified_domain)


def test_leak_check_refuses_unverified_domain(unverified_domain):
    with pytest.raises(PermissionError):
        check_leaked_credentials(unverified_domain, ["admin@example.com"])


def test_port_scan_gate_is_checked_before_looking_for_nmap_binary(unverified_domain, monkeypatch):
    """Regression guard: the verification check must happen BEFORE the nmap
    availability check, so that a misconfigured (nmap missing) environment
    doesn't accidentally make an unverified-domain scan look like a
    "tool not installed" error instead of the permission error it should be.
    """
    monkeypatch.setattr(port_scan.shutil, "which", lambda _: None)
    with pytest.raises(PermissionError):
        port_scan.scan_ports(unverified_domain)
