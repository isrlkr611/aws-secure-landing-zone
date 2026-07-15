"""Guards against the one mistake that would matter most in this
directory: someone adding a technique whose command isn't actually
read-only. Every YAML file in atomics/ is loaded and its safety
classification and command are sanity-checked.
"""

from pathlib import Path

import yaml

from orchestrator import ATOMICS_DIR, load_techniques

# Commands containing any of these are refused - deliberately blunt
# substring matching rather than a clever parser, because the goal is a
# loud, easy-to-audit allowlist-adjacent check, not perfect shell parsing.
DISALLOWED_SUBSTRINGS = [
    "rm ", "rm-", "mv ", "cp ", "chmod", "chown", "kill", "curl -X POST",
    "wget ", "curl -o", "curl --output", "dd ", "mkfs",
    "useradd", "userdel", "passwd", "sudo", "systemctl stop", "systemctl disable",
]


def _strip_devnull_redirects(command: str) -> str:
    """`2>/dev/null` (discard stderr) is safe and used throughout this
    library's fallback chains (`cmd1 || cmd2`). Strip those specific
    redirects before checking for a real ">" (write-to-file) below, so
    this test isn't blind to the difference between "discard output" and
    "write output somewhere that persists."
    """
    for pattern in ("2>/dev/null", "1>/dev/null", ">/dev/null"):
        command = command.replace(pattern, "")
    return command


def test_every_technique_file_parses_and_has_required_fields():
    techniques = load_techniques()
    assert len(techniques) > 0
    for t in techniques:
        assert t["attack_technique"].startswith("T")
        assert t["display_name"]
        assert t["tactic"]
        assert t["safety"] == "read_only", f"{t['attack_technique']} is not marked read_only"
        assert t["test"]["command"]


def test_every_technique_command_is_actually_read_only_by_our_own_definition():
    techniques = load_techniques()
    for t in techniques:
        command = t["test"]["command"]
        for bad in DISALLOWED_SUBSTRINGS:
            assert bad not in command, (
                f"{t['attack_technique']} command contains '{bad}', which is not "
                f"read-only - see purple-team/tests/test_atomics_library.py DISALLOWED_SUBSTRINGS"
            )
        sanitized = _strip_devnull_redirects(command)
        assert ">" not in sanitized, (
            f"{t['attack_technique']} command writes output somewhere "
            f"persistent (a '>' redirect that isn't just discarding to /dev/null)"
        )


def test_technique_ids_are_unique():
    techniques = load_techniques()
    ids = [t["attack_technique"] for t in techniques]
    assert len(ids) == len(set(ids))


def test_atomics_dir_has_no_orphan_non_technique_yaml():
    # every *.yaml file under atomics/ other than README.md should be a
    # valid technique starting with T (MITRE technique ID convention)
    for path in Path(ATOMICS_DIR).glob("*.yaml"):
        data = yaml.safe_load(path.read_text())
        assert data["attack_technique"] == path.stem
