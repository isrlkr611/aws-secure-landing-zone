import json
import subprocess
from unittest.mock import patch

import httpx
import respx

from app.services import subdomain_scan


def _fake_subfinder_completed_process(hosts: list[str]) -> subprocess.CompletedProcess:
    stdout = "\n".join(json.dumps({"host": h}) for h in hosts)
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr="")


def test_run_subfinder_parses_json_lines():
    with patch.object(
        subdomain_scan.subprocess,
        "run",
        return_value=_fake_subfinder_completed_process(["www.example.com", "api.example.com"]),
    ):
        hosts = subdomain_scan._run_subfinder("example.com", "subfinder")
    assert hosts == {"www.example.com", "api.example.com"}


def test_run_subfinder_missing_binary_returns_empty_set():
    with patch.object(subdomain_scan.subprocess, "run", side_effect=FileNotFoundError()):
        hosts = subdomain_scan._run_subfinder("example.com", "subfinder")
    assert hosts == set()


def test_run_subfinder_timeout_returns_empty_set():
    with patch.object(
        subdomain_scan.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="subfinder", timeout=120)
    ):
        hosts = subdomain_scan._run_subfinder("example.com", "subfinder")
    assert hosts == set()


@respx.mock
def test_query_crtsh_extracts_and_filters_hostnames():
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"name_value": "www.example.com\n*.staging.example.com"},
                {"name_value": "unrelated.other-domain.com"},
            ],
        )
    )
    with httpx.Client() as client:
        hosts = subdomain_scan._query_crtsh("example.com", client)
    assert hosts == {"www.example.com", "staging.example.com"}
    assert "unrelated.other-domain.com" not in hosts


@respx.mock
def test_enumerate_subdomains_merges_sources_and_enforces_gate(verified_domain):
    respx.get("https://crt.sh/").mock(
        return_value=httpx.Response(200, json=[{"name_value": "mail.example.com"}])
    )
    with patch.object(subdomain_scan, "_run_subfinder", return_value={"www.example.com"}):
        result = subdomain_scan.enumerate_subdomains(verified_domain)

    assert set(result["subdomains"]) == {"www.example.com", "mail.example.com", "example.com"}
    assert result["sources"]["subfinder"] == ["www.example.com"]
    assert result["sources"]["crtsh"] == ["mail.example.com"]


def test_diff_subdomains_detects_new_and_removed():
    diff = subdomain_scan.diff_subdomains(
        previous=["a.example.com", "b.example.com"],
        current=["b.example.com", "c.example.com"],
    )
    assert diff == {"added": ["c.example.com"], "removed": ["a.example.com"]}


def test_diff_subdomains_first_scan_has_no_previous():
    diff = subdomain_scan.diff_subdomains(previous=None, current=["a.example.com"])
    assert diff == {"added": ["a.example.com"], "removed": []}
