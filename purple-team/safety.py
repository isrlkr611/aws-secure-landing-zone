"""Lab-target authorization gate.

--- WHY THIS FILE EXISTS AND MUST NOT BE BYPASSED --------------------------
This orchestrator executes MITRE ATT&CK technique commands - even the
carefully curated, read-only-only subset in atomics/ (see
atomics/README.md) is still "running attacker tradecraft commands on a
machine." Running that against infrastructure you don't own or operate,
without a contract, is unauthorized computer use in the same sense
scanning an unverified domain is in platform/app/services/verification.py
- the two modules exist for the same reason and follow the same pattern:
default-deny, explicit-allow, and the check happens at every call site
that touches a target, not just once at the top of the program.

The default lab-config.yaml ships with exactly one entry: localhost,
pre-confirmed, because that's the only target this orchestrator can prove
you're authorized to run commands on without any external attestation
(it's the machine actually running this code). Adding any other host
requires manually editing that file and explicitly setting
confirmed_own_lab: true - a host merely being listed is not enough; the
schema requires that field to default to False so a copy-pasted new entry
stays blocked until someone deliberately flips it.
---------------------------------------------------------------------------
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

DEFAULT_LAB_CONFIG = Path(__file__).resolve().parent / "lab-config.yaml"

_LOCALHOST_ADDRESSES = {"127.0.0.1", "::1", "localhost"}


@dataclass
class LabHost:
    name: str
    address: str
    confirmed_own_lab: bool = False


def load_lab_config(path: Path = DEFAULT_LAB_CONFIG) -> dict[str, LabHost]:
    """Return {host_name: LabHost}. Missing/malformed entries fail loudly
    rather than being skipped - a silently-dropped entry could otherwise
    make an operator believe a host is gated when the config simply failed
    to parse it.
    """
    raw = yaml.safe_load(path.read_text()) or {}
    hosts = {}
    for entry in raw.get("hosts", []):
        host = LabHost(
            name=entry["name"],
            address=entry["address"],
            confirmed_own_lab=bool(entry.get("confirmed_own_lab", False)),
        )
        hosts[host.name] = host
    return hosts


def require_lab_target(host: LabHost) -> None:
    """Hard gate called at every point the orchestrator is about to run a
    command against `host`. Raises PermissionError unless the host is
    localhost/loopback OR has been explicitly confirmed in lab-config.yaml.

    Being localhost is not itself sufficient trust for a production
    security tool - it's sufficient here because "the machine running this
    process" is the one target this codebase can verify authorization for
    without any external attestation mechanism, the same way an
    unauthenticated `whoami` is trusted context in a shell.
    """
    is_loopback = host.address in _LOCALHOST_ADDRESSES
    if is_loopback:
        return
    if not host.confirmed_own_lab:
        raise PermissionError(
            f"Refusing to run techniques against '{host.name}' ({host.address}): "
            f"not localhost and not marked confirmed_own_lab: true in lab-config.yaml. "
            f"See purple-team/safety.py and purple-team/README.md."
        )
