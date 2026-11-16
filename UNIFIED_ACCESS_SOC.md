# Unified Access SOC v2

A permanent module inside Sentinel 2.0, enabled by the local launcher:

```bash
python run_unified_soc.py
```

Open http://127.0.0.1:5000/access-monitor. Use the same password as Access Lab.
Access Lab may keep running separately at http://127.0.0.1:5002 for simulated
badge presentations, badge status changes and door controls. Both applications
use the existing `~/.sentinel-access-lab/access.db`, unless configured otherwise.

## Features

- Polls every two seconds while the dashboard is open; in-page alerts for newly
  observed cases and correlation signals. Background tabs may refresh less often.
- Combines sampled access events and Sentinel's retained network feed. Offline
  IDS entries are labeled when available. Badges are not assigned network IPs.
- Opens saved case evidence, writes analyst notes, and changes case status
  directly in the same Access Lab database. Each edit creates an audit record
  with actor `unified-soc-admin`. Badge and door controls remain in Access Lab.
- Exports the displayed monitoring snapshot and correlation evidence as JSON.
  Full case evidence/notes remain in the original Access Lab JSON export.
- Operator login reuses the Access Lab password hash. The SOC cookie is signed,
  HTTP-only, and SameSite Strict. Writes require a CSRF token. Password resets
  invalidate existing SOC sessions. Failed logins are throttled locally.

## Correlation rules

| Rule | Exact trigger | Severity |
|---|---|---|
| MULTI_DOOR_DENIALS | One badge denied at 3 or more distinct doors in 120 seconds | Medium |
| DENIAL_THEN_FORCED_DOOR | At least 5 denials by one badge followed by a forced-door sensor event at the same door within 120 seconds | High |

These are patterns to investigate. They do not establish who caused an opening.
Correlation signals are recomputed from the latest 2,000 access events and are
not inserted as new Access Lab cases. Historical signals remain in that sample.
Signals have event evidence and may be exported for a training investigation.

## Try it

1. Start Access Lab and the Unified SOC.
2. In Access Lab, present SIM-UNKNOWN at the lobby, office and server-room doors
   within two minutes. The multi-door signal appears on the next SOC refresh.
3. Run Repeated denials to create a saved Access Lab case.
4. Open Investigate in the SOC, review the exact events, add a note and resolve
   the case. Refresh the same case in Access Lab to verify the update.
5. For the second correlation rule, present SIM-UNKNOWN at the loading entrance
   five times, then run Forced-door sensor within two minutes.

## Bounds and persistence

- Source database is opened in read-only mode for snapshots, with a consistent
  transaction. Authenticated case edits use an atomic read/write transaction.
- Access event count and open-case count cover the whole database. The timeline
  shows at most 140 events, sampled from 120 access and 70 retained network events.
- Queue displays the latest 200 cases. Case detail displays latest 200 linked
  events and 100 notes, with total counts shown.
- Source event timestamps are converted to numeric time for sorting; browser
  display uses local time. Invalid network timestamps display as Unknown time.
- No automatic source data deletion, badge reset, or database reset occurs.
- `.access_soc/` contains the SOC signing key, login-attempt database, local
  configuration and installer backups. Keep it out of Git.
- The installer backs up replaced files and checks compatibility before writing.

## Local boundary

The module remains disabled unless ENABLE_ACCESS_SOC=1 is set. The launcher
binds to 127.0.0.1. Module endpoints also restrict source address and host.
This is a fictional local lab, not a workplace RFID or physical-door integration.
Do not enable it as-is on public hosting: proxying and public authentication
require a separate design. The original Sentinel homepage is not protected by
this module's operator login. Monitoring requests to this module are protected.

## Tests

The installer tests this module with temporary source databases and the actual
Sentinel startup code. For manual testing, provide Access Lab's module directory
on PYTHONPATH and optionally set SOC_TEST_APP to the Sentinel app.py path:

```bash
PYTHONPATH="$HOME/sentinel-access-lab:$PWD" python test_access_soc.py
```

Tests cover source events, case evidence, audited edits, login, CSRF, locality,
password reset, timestamp ordering, exports and positive/negative correlations.
