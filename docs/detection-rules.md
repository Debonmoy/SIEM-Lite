# Detection rules

This document describes every built-in detection rule, how it is configured, and
how to tune it. Rules operate only on normalized `Event` objects; they do not
parse logs and do not write to the database.

## How rules are loaded

1. `siem/config.py` defines `DEFAULT_RULES`.
2. `config/detection_rules.json` (or `MINISIEM_RULES`) is deep-merged over the
   defaults.
3. `DetectionEngine` instantiates only rules with `"enabled": true`.
4. `RiskEngine` assigns final severity using the same merged configuration.

A malformed rule file is ignored and defaults are used, so a typo cannot prevent
the tool from running. Use `python main.py rules --json` to inspect the
**effective** configuration.

## Counting model

Most threshold rules use `densest_window(events, window_seconds)`:

- Events without a valid timestamp are excluded from window calculations.
- Events are sorted by epoch.
- A sliding window finds the largest group whose first and last timestamps differ
  by at most the configured window.

This avoids the common mistake of comparing the first and last event over an
entire file. An attacker can spread attempts out, and that will correctly not
trigger a short-window rule.

## Common fields

| Field | Meaning |
| --- | --- |
| `rule_id` | Stable identifier, also stored on alerts |
| `category` | Grouping used by the dashboard/report |
| `severity` | Base severity before risk escalation |
| `dedup_key` | Suppresses duplicate open alerts |
| `event_count` | Number of events in the triggering window/group |
| `evidence` | Up to 20 compact event summaries (21 for success-after-failure) |
| `recommended_actions` | Analyst next steps |
| `context` | Numbers used by `RiskEngine` |

---

## `ssh_brute_force`

- **File:** `siem/detection/brute_force.py`
- **Category:** `brute_force`
- **Input:** events with `log_format` in `auth`/`ssh`, `auth_result == "failure"`,
  and a valid `source_ip`.
- **Logic:** group failures by source IP; take the densest window; fire when the
  count is at least `threshold`.
- **Defaults:** `threshold: 10`, `window_seconds: 300`, base `HIGH`.
- **Dedup:** `ssh_brute_force:<ip>`.
- **Risk escalation:** +1 at 2x threshold, +2 at 3x, +1 when distinct usernames
  reach `username_escalation_count` (default 3).
- **Tuning:**
  - Lower the threshold for small labs, raise it for noisy shared NAT.
  - Increase the window if attempts are slow and low.
  - Add trusted scanners to `suspicious_ip.allowlist`, but note that the SSH rule
    does not consult the allowlist; disable the rule or raise its threshold if a
    known scanner triggers it.
- **False positives:** forgotten passwords, automated jobs with stale
  credentials, vulnerability scanners, shared NAT egress.

## `success_after_failures`

- **File:** `siem/detection/brute_force.py`
- **Category:** `authentication_anomaly`
- **Input:** Linux auth/SSH successes and failures with a source IP.
- **Logic:** for each success, count failures from the same IP in
  `[success - window, success]`; fire when at least `failure_threshold`.
- **Defaults:** `failure_threshold: 5`, `window_seconds: 600`, base `HIGH`.
- **Dedup:** `success_after_failures:<ip>`.
- **Evidence:** up to 20 failures plus the success.
- **Tuning:** raise the failure threshold where users routinely mistype; shorten
  the window to focus on immediate success after failure.
- **False positives:** a user who mistypes several times then succeeds; a
  legitimate script retrying with corrected credentials.
- **Why it matters:** a success after many failures is the classic signature of a
  successful password-guessing attempt, but it is not proof.

## `port_scan`

- **File:** `siem/detection/port_scan.py`
- **Category:** `network_scan`
- **Input:** events with `source_ip` and `destination_port`.
- **Logic:** group by source IP; densest window; fire when distinct destination
  ports reach `distinct_port_threshold` and the window has at least
  `failed_threshold` events (failures are counted, but total events also satisfy
  the minimum).
- **Defaults:** `distinct_port_threshold: 10`, `failed_threshold: 5`,
  `window_seconds: 300`, base `MEDIUM`.
- **Dedup:** `port_scan:<ip>`.
- **Risk escalation:** +1 at 50+ distinct ports.
- **Important:** authentication logs have no destination ports, so this rule will
  not fire on SSH failures. It is designed for firewall/netfilter logs and
  network security events. The sample `firewall.log` uses `SRC/DST/SPT/DPT`
  key-value fields parsed by the generic parser.
- **False positives:** authorized scanners, monitoring, NAT behavior, load
  balancers probing backends.

## `suspicious_ip`

- **File:** `siem/detection/suspicious_ip.py`
- **Category:** `suspicious_ip`
- **Input:** any event with a source IP not on the allowlist.
- **Logic:**
  - Denylist: every IP on the configured denylist that appears in events produces
    a finding with severity bumped one level.
  - Frequency: failures per IP in the densest window at or above
    `failure_threshold` produce a finding.
- **Defaults:** `failure_threshold: 20`, `window_seconds: 600`, base `MEDIUM`,
  `allowlist: ["127.0.0.1", "::1"]`, empty denylist.
- **Dedup:** `suspicious_ip_denylist:<ip>` and `suspicious_ip_frequency:<ip>`.
- **Context:** includes `private_ip` (true/false/unknown) so analysts know whether
  the source is internal.
- **Tuning:** add known-bad IPs to `denylist`; add trusted internal ranges or
  scanners to `allowlist`. Allowlisting suppresses both denylist and frequency
  findings for that IP.
- **False positives:** internal misconfigured clients, monitoring, shared egress.

## `web_attack_*`

- **File:** `siem/detection/web_attacks.py`
- **Category:** `web_attack`
- **Input:** events with a web format (`apache_access`, `apache_error`,
  `nginx_access`, `nginx_error`), `event_type` `http_request`/`http_error`, or any
  `http_status`.
- **Logic:** match `request_path` + `raw_message` against configured patterns,
  both raw and URL-decoded (`unquote`, `unquote_plus`). One finding per
  `(category, source_ip)`.
- **Categories and base severities:**
  - `sql_injection` -> HIGH
  - `directory_traversal` -> HIGH
  - `xss` -> MEDIUM
  - `sensitive_files` -> MEDIUM
- **Rule IDs:** `web_attack_sql_injection`, `web_attack_xss`,
  `web_attack_directory_traversal`, `web_attack_sensitive_files`.
- **Dedup:** `web_attack_<category>:<ip>`.
- **Risk escalation:** +1 at 10+ matching requests for the same category/IP.
- **Patterns:** see `config/detection_rules.json`. If you supply `patterns`, the
  supplied mapping replaces the **entire** default pattern mapping, so copy the
  full default block and edit it rather than providing only one category.
- **False positives:** security scanners, WAF tests, developers testing input
  handling, legitimate filenames containing pattern-like text.
- **Note:** a match indicates suspicious request content, not successful
  exploitation. Correlate with response status and application logs.

## `web_auth_failures`

- **File:** `siem/detection/web_attacks.py`
- **Category:** `web_attack`
- **Input:** web events with `http_status` 401 or 403 and a source IP.
- **Logic:** densest window at or above `auth_failure_threshold`.
- **Defaults:** 20 responses / 300 s, base `MEDIUM`.
- **Dedup:** `web_auth_failures:<ip>`.
- **False positives:** misconfigured clients, expired sessions, password sprays
  that are actually legitimate retries, scraping.

---

## Windows Security rules

All Windows rules are implemented in `siem/detection/windows_events.py` and
require `os_source == "windows"` or a `windows_*` log format. Event data is read
from `event.extra["event_data"]` with case-insensitive fallback.

### `windows_failed_logon` (4625)

- Group by `source_ip` if present, otherwise `username`.
- Densest window at or above `failed_logon_threshold` (default 5 / 600 s).
- Base severity from `rule_severities["4625"]` (default MEDIUM); +1 at 2x.
- Dedup: `windows_failed_logon:<key>`.
- False positives: stale services, mapped drives, user error.

### `windows_account_lockout` (4740)

- Any lockout, grouped by user or host.
- Base `HIGH`, risk floor HIGH.
- Dedup: `windows_account_lockout:<key>`.

### `windows_audit_cleared` (1102)

- Any audit-log clear, grouped by host.
- Base `CRITICAL`; risk engine always forces CRITICAL.
- Dedup: `windows_audit_cleared:<host>`.
- High signal: clearing the Security log destroys evidence. Verify authorized
  maintenance, but treat unexpected clears as serious.

### `windows_account_created` (4720)

- Any account creation, grouped by target user.
- Base `MEDIUM`.
- Dedup: `windows_account_created:<user>`.

### `windows_group_membership_change` (4728/4732)

- Grouped by `(MemberName/MemberSid, GroupName/TargetUserName)`.
- Base `MEDIUM`.
- Dedup: `windows_group_membership:<group>:<member>`.
- Privileged group changes are a common persistence technique.

### `windows_explicit_credentials` (4648)

- Grouped by `(user, source_ip)`.
- Base `MEDIUM`.
- Dedup: `windows_explicit_credentials:<user>:<ip>`.

### `windows_special_privileges` (4672)

- Grouped by user.
- Base `LOW`; administrative logons routinely produce this. Treat as context.

### `windows_service_installed` (4697)

- Grouped by `(host, service name or image path)`.
- Base `MEDIUM`.
- Dedup: `windows_service_installed:<host>:<service>`.

### `windows_suspicious_process` (4688)

- Fires when the process basename is in a dual-use list: PowerShell, pwsh, WMIC,
  certutil, mshta, rundll32, regsvr32, psexec, psexesvc, bitsadmin, cscript,
  wscript, nltest, vssadmin, bcdedit, schtasks.
- Base `INFO`; this is deliberately low because these binaries are common in
  administration. Review command line and parent process.
- Dedup: `windows_suspicious_process:<host>:<process>`.

### `windows_remote_logon` (4624)

- Logon type 10 (RDP/remote interactive) from any source.
- Logon type 3 (network) only when the source IP is public (not private).
- Grouped by `(user, ip, logon_type)`.
- Base `MEDIUM`.
- Dedup: `windows_remote_logon:<user>:<ip>:<type>`.

### `windows_success_after_failures` (4624 after 4625)

- For each successful 4624 with a source IP, count 4625 events from the same IP
  in the preceding window; fire at `failed_logon_threshold`.
- Base `HIGH`.
- Dedup: `windows_success_after_failures:<ip>`.
- Note: the same success can also produce `windows_remote_logon`; that is
  intentional because they answer different questions.

---

## Risk escalation summary

| Condition | Effect |
| --- | --- |
| SSH failures >= 2x threshold | +1 severity level |
| SSH failures >= 3x threshold | +2 severity levels |
| SSH distinct usernames >= `username_escalation_count` | +1 severity level |
| Success after failures | at least HIGH |
| Audit log cleared | CRITICAL |
| Account lockout | at least HIGH |
| Port scan >= 50 distinct ports | +1 severity level |
| Web attack >= 10 matching requests | +1 severity level |
| Windows failed logons >= 2x threshold | +1 severity level |

Severity never exceeds CRITICAL and never drops below the rule's base severity.
Every explanation ends with the heuristic disclaimer.

## Tuning workflow

1. Inspect effective config: `python main.py rules --json`.
2. Reproduce with a small file: `python main.py offline --file path.log`.
3. Inspect alerts: `python main.py alerts --json`.
4. Adjust thresholds or patterns in `config/detection_rules.json`.
5. Re-run and confirm both positive and negative cases.
6. Run `pytest -q` if you changed code, not just configuration.

## Adding a new rule

1. Create a module in `siem/detection/` with a `BaseRule` subclass.
2. Return `Finding` objects with a stable `rule_id`, `category`, `severity`,
   `title`, `description`, `explanation`, `evidence`, `recommended_actions` and a
   `dedup_key`.
3. Add defaults to `DEFAULT_RULES` and the JSON config.
4. Instantiate it in `DetectionEngine._build_rules`.
5. Add risk logic in `RiskEngine.assess` if needed.
6. Add tests covering threshold boundary, wrong format, and dedup.

## Testing rules

- `tests/test_detection.py` contains positive and negative cases for every rule
  family, including Windows.
- Use the `make_event` fixture to build minimal events.
- Use the `rules` fixture to load the real configuration.
- Prefer boundary tests: threshold - 1, threshold, threshold + 1.
