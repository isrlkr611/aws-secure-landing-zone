"""Port/service exposure scanning via nmap.

Unlike subdomain enumeration, this DOES send traffic directly to the
target's infrastructure - it is the step where "scanning a domain you
don't have authorization for" stops being an abstract policy statement and
becomes a live TCP connection someone else's IDS will see. Two independent
safeguards apply here, not just the domain-level verification gate:

1. `require_verified(domain)` - same legal gate as every other scan type.
2. A conservative, non-configurable-by-the-caller rate cap
   (`settings.nmap_max_rate`, default 100 pkt/s) and a fixed, small port
   list rather than a full 1-65535 sweep - this is an attack-surface
   *monitor*, not a penetration testing tool, and the scan profile
   reflects that on purpose.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET

from app.config import get_settings
from app.models import Domain
from app.services.verification import require_verified

logger = logging.getLogger(__name__)


class NmapNotAvailable(RuntimeError):
    pass


def _build_nmap_command(target: str, binary: str, ports: str, max_rate: int) -> list[str]:
    return [
        binary,
        "-Pn",  # skip host discovery ping - many hosts firewall ICMP, this only probes the port list below
        "-sT",  # TCP connect scan - no raw sockets, no CAP_NET_RAW requirement, easiest to run unprivileged in a container
        "-p", ports,
        "--max-rate", str(max_rate),
        "--host-timeout", "60s",
        "-oX", "-",  # XML to stdout
        target,
    ]


def _parse_nmap_xml(xml_output: str) -> list[dict]:
    root = ET.fromstring(xml_output)
    open_ports: list[dict] = []
    for host in root.findall("host"):
        for ports_el in host.findall("ports"):
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                open_ports.append(
                    {
                        "port": int(port_el.get("portid")),
                        "protocol": port_el.get("protocol"),
                        "service": service_el.get("name") if service_el is not None else None,
                        "product": service_el.get("product") if service_el is not None else None,
                        "version": service_el.get("version") if service_el is not None else None,
                    }
                )
    return open_ports


def scan_ports(domain: Domain) -> dict:
    """Scan `domain.name` for open ports among the configured common-port
    list. Raises PermissionError if the domain is not verified, and
    NmapNotAvailable if the nmap binary isn't installed in this environment
    (deliberately not silently skipped, unlike the passive subfinder source
    in subdomain_scan.py - a missing active scanner should be loud, not
    quietly produce an empty "no open ports" result that looks like a clean
    bill of health).
    """
    require_verified(domain)
    settings = get_settings()

    if shutil.which(settings.nmap_binary) is None:
        raise NmapNotAvailable(
            f"'{settings.nmap_binary}' is not installed in this environment."
        )

    command = _build_nmap_command(
        target=domain.name,
        binary=settings.nmap_binary,
        ports=settings.scan_common_ports,
        max_rate=settings.nmap_max_rate,
    )
    logger.info("Running port scan for verified domain %s", domain.name)
    proc = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap exited {proc.returncode}: {proc.stderr[:500]}")

    open_ports = _parse_nmap_xml(proc.stdout)
    return {"target": domain.name, "open_ports": open_ports}


def diff_ports(previous: list[dict] | None, current: list[dict]) -> dict:
    """Compare two port scans by (port, protocol) tuples - a newly-opened
    port is the classic "someone stood up a service and forgot to firewall
    it" signal this platform exists to catch.
    """

    def _key(entry: dict) -> tuple[int, str]:
        return (entry["port"], entry["protocol"])

    previous_map = {_key(e): e for e in (previous or [])}
    current_map = {_key(e): e for e in current}

    opened = [current_map[k] for k in current_map.keys() - previous_map.keys()]
    closed = [previous_map[k] for k in previous_map.keys() - current_map.keys()]
    return {"opened": opened, "closed": closed}
