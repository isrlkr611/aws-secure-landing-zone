import subprocess
from unittest.mock import patch

import pytest

from app.services import port_scan

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.25.0"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="conn-refused"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml_only_returns_open_ports():
    open_ports = port_scan._parse_nmap_xml(SAMPLE_NMAP_XML)
    ports = {p["port"] for p in open_ports}
    assert ports == {443, 8080}


def test_parse_nmap_xml_extracts_service_metadata():
    open_ports = port_scan._parse_nmap_xml(SAMPLE_NMAP_XML)
    https_entry = next(p for p in open_ports if p["port"] == 443)
    assert https_entry["service"] == "https"
    assert https_entry["product"] == "nginx"
    assert https_entry["version"] == "1.25.0"


def test_build_nmap_command_uses_conservative_rate_and_connect_scan():
    command = port_scan._build_nmap_command("example.com", "nmap", "80,443", max_rate=100)
    assert "-sT" in command  # TCP connect scan, not a raw-socket SYN scan
    assert "--max-rate" in command
    assert command[command.index("--max-rate") + 1] == "100"
    assert command[-1] == "example.com"


def test_scan_ports_raises_when_nmap_not_installed(verified_domain, monkeypatch):
    monkeypatch.setattr(port_scan.shutil, "which", lambda _: None)
    with pytest.raises(port_scan.NmapNotAvailable):
        port_scan.scan_ports(verified_domain)


def test_scan_ports_returns_parsed_open_ports(verified_domain, monkeypatch):
    monkeypatch.setattr(port_scan.shutil, "which", lambda _: "/usr/bin/nmap")
    fake_result = subprocess.CompletedProcess(args=[], returncode=0, stdout=SAMPLE_NMAP_XML, stderr="")
    with patch.object(port_scan.subprocess, "run", return_value=fake_result):
        result = port_scan.scan_ports(verified_domain)
    assert result["target"] == verified_domain.name
    assert {p["port"] for p in result["open_ports"]} == {443, 8080}


def test_scan_ports_raises_on_nonzero_exit(verified_domain, monkeypatch):
    monkeypatch.setattr(port_scan.shutil, "which", lambda _: "/usr/bin/nmap")
    fake_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="permission denied")
    with patch.object(port_scan.subprocess, "run", return_value=fake_result):
        with pytest.raises(RuntimeError):
            port_scan.scan_ports(verified_domain)


def test_diff_ports_detects_opened_and_closed():
    previous = [{"port": 22, "protocol": "tcp", "service": "ssh"}]
    current = [{"port": 443, "protocol": "tcp", "service": "https"}]
    diff = port_scan.diff_ports(previous, current)
    assert diff["opened"] == current
    assert diff["closed"] == previous
