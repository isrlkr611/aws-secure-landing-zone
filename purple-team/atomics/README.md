# Curated safe technique subset

Real MITRE ATT&CK technique IDs, modeled on the structure Atomic Red Team's own atomics library uses (`attack_technique`, `test.command`, platform tags), but a hand-curated subset of 7 rather than the full public library, chosen for one property: **every command here is read-only reconnaissance** - it inspects local system state and prints it; it does not create, modify, or delete anything, does not touch the network beyond loopback, and does not require elevated privileges.

| Technique | Tactic | What it runs |
|---|---|---|
| [T1082](T1082.yaml) System Information Discovery | Discovery | `uname -a`, `/etc/os-release` |
| [T1033](T1033.yaml) System Owner/User Discovery | Discovery | `whoami`, `id` |
| [T1057](T1057.yaml) Process Discovery | Discovery | `ps aux` |
| [T1016](T1016.yaml) System Network Configuration Discovery | Discovery | `ip a`, `/etc/resolv.conf` |
| [T1018](T1018.yaml) Remote System Discovery | Discovery | `ip neigh` (ARP/neighbor table) |
| [T1007](T1007.yaml) System Service Discovery | Discovery | `systemctl list-units --type=service` |
| [T1083](T1083.yaml) File and Directory Discovery | Discovery | `ls -la` on a small set of common paths |

This is deliberately narrow. Atomic Red Team's public library includes hundreds of techniques across every tactic, many of which create files, modify registry/config, spawn persistence mechanisms, or are Windows-specific and would need a cleanup step to be safe to run more than once. Extending this set means adding a new `atomics/T####.yaml` file **and** getting the safety classification right - see `orchestrator.py`'s `SAFETY_LEVELS` and the note in `README.md` "Extending the technique library" before adding anything beyond pure discovery/recon.
