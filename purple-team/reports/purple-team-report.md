# Purple Team Detection Coverage Report

Target: `localhost` · Detector: `null`

**Detection coverage: 0/7 (0.0%)**

| Technique | Tactic | Executed | Exit code | Detected | Evidence |
|---|---|---|---|---|---|
| `T1007` System Service Discovery | discovery | yes | 0 | ❌ no | No detection stack configured - see purple-team/README.md 'Detectors'. |
| `T1016` System Network Configuration Discovery | discovery | yes | 0 | ❌ no | No detection stack configured - see purple-team/README.md 'Detectors'. |
| `T1018` Remote System Discovery | discovery | yes | 0 | ❌ no | No detection stack configured - see purple-team/README.md 'Detectors'. |
| `T1033` System Owner/User Discovery | discovery | yes | 0 | ❌ no | No detection stack configured - see purple-team/README.md 'Detectors'. |
| `T1057` Process Discovery | discovery | yes | 0 | ❌ no | No detection stack configured - see purple-team/README.md 'Detectors'. |
| `T1082` System Information Discovery | discovery | yes | 0 | ❌ no | No detection stack configured - see purple-team/README.md 'Detectors'. |
| `T1083` File and Directory Discovery | discovery | yes | 0 | ❌ no | No detection stack configured - see purple-team/README.md 'Detectors'. |

**Every executed technique went undetected.** If a detection stack (Wazuh, GuardDuty) is expected to be watching this target, this is the finding that matters - it means either the stack isn't deployed, isn't tuned for these technique IDs, or the alert pipeline has a gap. If no detection stack is deployed at all (the current state of the landing zone in this repo - see docs/architecture.md), this is the expected, honest result, not a failure of this tool.
