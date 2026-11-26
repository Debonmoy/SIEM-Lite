# Educational walkthrough: from a raw log line to a triaged alert

This walkthrough explains how the Mini SIEM works by following real sample data
through every stage. It is written for learners who want to understand both the
code and the security reasoning behind it.

Run the commands from the repository root with the virtual environment active.

> Ethical note: only analyze logs from systems you own or are authorized to
> inspect. The bundled samples are synthetic or public test fixtures. Detection
> is not prevention; never use this tool to justify blocking or accusing someone
> without verification.

---

## 1. What a SIEM actually does

A SIEM (Security Information and Event Management) system is usually described
as four capabilities:

1. **Collection** - gather logs from many sources.
2. **Normalization** - turn different formats into a common schema.
3. **Detection** - apply rules, correlations or analytics.
4. **Response support** - alert, explain, prioritize and track investigation.

This project implements a small version of each. The important mental model is:

- An **event** is an observation: "a login failed at 09:50:01 from 203.0.113.50".
- A **finding** is a rule's conclusion: "this looks like brute force".
- An **alert** is a persisted, scored, deduplicated finding that a human can
  triage.

Events are facts. Alerts are hypotheses. Treating an alert as proof is the most
common beginner mistake.

---

## 2. The pipeline at a glance

```
raw log line
   -> parser            (format-specific field extraction)
   -> Event             (normalized schema)
   -> normalizer        (validation, timestamp, fingerprint)
   -> detection rule    (windowed logic)
   -> Finding           (rule conclusion + evidence)
   -> risk engine       (final severity + rationale)
   -> alert manager     (dedup + persistence)
   -> CLI / dashboard   (human triage)
```

Each stage is deliberately separate. You can inspect the output of any stage
without running the whole tool.

---

## 3. Walkthrough A: SSH brute force

### 3.1 The raw input

`sample_logs/linux/auth.log` starts with:

```
Jan 15 09:50:00 web01 sshd[2200]: Failed password for invalid user admin from 203.0.113.50 port 41001 ssh2
```

This is a syslog line with:

- a timestamp without a year (`Jan 15 09:50:00`),
- a host (`web01`),
- a program and PID (`sshd[2200]`),
- a message containing the outcome, username, source IP and source port.

### 3.2 Parsing

The registry selects the `auth` parser for this file. The parser:

1. Splits the syslog prefix into timestamp, host and remainder.
2. Extracts `program[pid]: message`.
3. Matches the message against known sshd patterns.
4. Produces an `Event`.

Inspect it:

```bash
python - <<'PY'
from siem.parsers.registry import ParserRegistry

result = ParserRegistry().parse_file("sample_logs/linux/auth.log")
print("parser:", result.parser_name)
print("events:", len(result.events))
event = result.events[0]
for field in ("timestamp", "host", "service", "username", "source_ip",
              "source_port", "auth_result", "event_type"):
    print(f"{field:14}: {getattr(event, field)}")
PY
```

Expected highlights:

```
parser: auth
events: 17
timestamp     : <current year>-01-15T09:50:00+00:00
host          : web01
service       : sshd
username      : admin
source_ip     : 203.0.113.50
source_port   : 41001
auth_result   : failure
event_type    : ssh_login_failed
```

Notice that the parser **did not decide anything is malicious**. It only
extracted fields. The year is inferred from the current year at parse time because
syslog timestamps omit it (for example, 2026 when parsed in 2026).

### 3.3 Normalization

The normalizer validates IPs and ports, tags the OS, computes `timestamp_epoch`
and creates a fingerprint. Invalid values become `None` rather than fabricated
data.

```bash
python - <<'PY'
from siem.parsers.registry import ParserRegistry
from siem.analysis.event_normalizer import EventNormalizer

parsed = ParserRegistry().parse_file("sample_logs/linux/auth.log")
events, duplicates = EventNormalizer().normalize_many(parsed.events)
print("normalized:", len(events), "duplicates:", duplicates)
print("epoch:", events[0].timestamp_epoch)
print("fingerprint:", events[0].fingerprint[:16], "...")
PY
```

The fingerprint is used later to prevent ingesting the same record twice.

### 3.4 Detection

The SSH rule:

1. Keeps Linux auth/SSH failures that have a source IP.
2. Groups them by source IP.
3. Finds the densest 300-second window.
4. Fires when the count reaches 10.

Run the rule directly:

```bash
python - <<'PY'
from siem.analysis.event_normalizer import EventNormalizer
from siem.config import load_rules
from siem.detection.detection_engine import DetectionEngine
from siem.parsers.registry import ParserRegistry

parsed = ParserRegistry().parse_file("sample_logs/linux/auth.log")
events, _ = EventNormalizer().normalize_many(parsed.events)
findings = DetectionEngine(load_rules()).run(events)
for f in findings:
    print(f.rule_id, "|", f.severity, "|", f.source_ip, "|", f.event_count)
PY
```

You should see `ssh_brute_force` for `203.0.113.50` with 12 events, and
`success_after_failures` for the same IP.

Why 12? The sample contains 12 failures between 09:50:00 and 09:50:11, then a
success at 09:55:20. The failure burst is dense enough for the 10-in-300-seconds
rule. The later success, preceded by 12 failures within 600 seconds, triggers the
second rule.

### 3.5 Risk scoring

The rule's base severity is HIGH. The risk engine adds context:

- 12 failures is above the threshold of 10 but below 2x (20), so no volume bump.
- 7 distinct usernames were targeted, which meets the default
  `username_escalation_count` of 3, so severity increases by one level.

Result: **CRITICAL**.

```bash
python - <<'PY'
from siem.analysis.event_normalizer import EventNormalizer
from siem.analysis.risk_engine import RiskEngine
from siem.config import load_rules
from siem.detection.detection_engine import DetectionEngine
from siem.parsers.registry import ParserRegistry

rules = load_rules()
parsed = ParserRegistry().parse_file("sample_logs/linux/auth.log")
events, _ = EventNormalizer().normalize_many(parsed.events)
for finding in DetectionEngine(rules).run(events):
    severity, explanation = RiskEngine(rules).assess(finding)
    print(f"{finding.rule_id}: {severity}")
    print(" ", explanation)
PY
```

This is why the CLI summary shows the SSH alert as CRITICAL while the rule's
configured base is HIGH. The escalation is explicit, not hidden.

### 3.6 The alert

The alert manager stores:

- a stable rule id and category,
- final severity,
- source IP and username,
- event count,
- evidence (compact event summaries),
- an explanation and recommended actions,
- a dedup key.

The dedup key `ssh_brute_force:203.0.113.50` means a second run will not create a
duplicate while the first alert is still `NEW` or `INVESTIGATING`. If the new
finding has a larger event count, the existing alert's count is updated.

### 3.7 Triage questions

A real analyst would ask:

1. Was the source IP expected? Is it internal, a known scanner, or external?
2. Which accounts were targeted? Were any privileged?
3. Did any attempt succeed? If so, what happened next?
4. Are other hosts seeing the same source?
5. Is there a change ticket or authorized penetration test?

The alert's recommended actions mirror these questions. The tool provides
evidence and context; it does not provide the answer.

---

## 4. Walkthrough B: web attack indicators

### 4.1 Raw input

From `sample_logs/linux/apache_access.log`:

```
203.0.113.66 - - [15/Jan/2024:09:05:05 +0000] "GET /search?q=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 900 "-" "sqlmap/1.7"
```

### 4.2 Parsing

The Apache access parser extracts client IP, timestamp, method, path, status and
user agent. The path is stored **as sent**, including percent-encoding.

### 4.3 Detection and decoding

The web rule checks both the raw path/message and URL-decoded versions. That is
important: `%20UNION%20SELECT` only matches the SQL-injection pattern after
decoding. The rule also matches the user agent? No - only the request path and
raw message are searched. In this line, the raw message contains the encoded
path, and the decoded form reveals `UNION SELECT`.

The rule creates `web_attack_sql_injection` for the source IP. It does not assume
the attack succeeded, even though the response is 200. A 200 could be a generic
error page, a search page reflecting input, or a real data leak. Correlation with
application behavior is required.

### 4.4 Why one alert per category and IP

The sample has multiple SQLi attempts from `203.0.113.66`. The rule aggregates
them into one finding with a count, rather than one alert per request. This keeps
the alert queue usable. The evidence list preserves the individual requests.

### 4.5 Other categories in the sample

- `../../../../etc/passwd` -> `web_attack_directory_traversal`
- `<script>alert(1)</script>` -> `web_attack_xss`
- `/.env`, `/.git/config` -> `web_attack_sensitive_files`
- 22 responses with 401/403 -> `web_auth_failures`

Inspect the rule IDs:

```bash
python - <<'PY'
from siem.analysis.event_normalizer import EventNormalizer
from siem.config import load_rules
from siem.detection.web_attacks import WebAttackRule
from siem.parsers.registry import ParserRegistry

parsed = ParserRegistry().parse_file("sample_logs/linux/apache_access.log")
events, _ = EventNormalizer().normalize_many(parsed.events)
rule = WebAttackRule(load_rules()["rules"]["web_attack"])
for f in rule.evaluate(events):
    print(f.rule_id, "|", f.severity, "|", f.source_ip, "|", f.event_count)
PY
```

---

## 5. Walkthrough C: Windows EVTX and Security events

### 5.1 EVTX is a container

EVTX is a binary Windows event log. The parser uses `python-evtx` to read records
and converts each record to XML, then reuses the XML normalization logic. This is
why EVTX analysis works on Linux and WSL without a Windows host.

```bash
python - <<'PY'
from siem.parsers.registry import ParserRegistry

result = ParserRegistry().parse_file("sample_logs/windows/new-user-security.evtx")
print("parser:", result.parser_name, "events:", len(result.events))
for e in result.events:
    print(e.event_code, e.timestamp, e.host, e.username, e.event_type)
PY
```

### 5.2 Event data mapping

Windows events carry most useful fields in `EventData`. The common builder maps:

- `TargetUserName` / `SubjectUserName` -> `username`
- `IpAddress` / `SourceNetworkAddress` -> `source_ip`
- `IpPort` / `SourcePort` -> `source_port`
- `NewProcessName` / `Image` -> `request_path` for process/service events
- `EventID` -> `event_code`
- 4624 -> `auth_result = "success"`, 4625 -> `"failure"`

The full `EventData` dictionary is preserved in `event.extra["event_data"]` for
rules and analysts.

### 5.3 Group membership mapping

For 4728/4732, the added member is in `MemberName`/`MemberSid` and the group is
in `GroupName`/`TargetUserName`. The rule uses both so it can report
"attacker added to Domain Admins" instead of guessing.

### 5.4 Rule families

Run the Windows rules on the sample JSON:

```bash
python - <<'PY'
from siem.analysis.event_normalizer import EventNormalizer
from siem.config import load_rules
from siem.detection.windows_events import WindowsSecurityRule
from siem.parsers.registry import ParserRegistry

parsed = ParserRegistry().parse_file("sample_logs/windows/security_events.json")
events, _ = EventNormalizer().normalize_many(parsed.events)
rule = WindowsSecurityRule(load_rules()["rules"]["windows_security"])
for f in rule.evaluate(events):
    print(f.rule_id, "|", f.severity, "|", f.username, "|", f.event_count)
PY
```

Expected rule IDs include failed logons, lockout, audit cleared, account created,
group change, explicit credentials, special privileges, service installed,
suspicious process, remote logon, and success after failures.

### 5.5 Why 1102 is CRITICAL

Clearing the Security audit log destroys evidence. It can be legitimate
maintenance, but because it removes the data needed to investigate everything
else, the risk engine forces CRITICAL regardless of the rule's base severity.
This is a good example of context changing risk: one event can matter more than a
hundred noisy ones.

### 5.6 Duplicate formats

If you analyze the XML, CSV, JSON and EVTX exports of the same events, you will
see more events than the logical count. Fingerprints include the format and raw
message, so cross-format duplicates are not merged. Choose one export per source
when exact counts matter.

---

## 6. Walkthrough D: port scan from firewall logs

`sample_logs/linux/firewall.log` contains netfilter-style records:

```
2024-01-15T09:20:00Z fw kernel: [UFW BLOCK] ... SRC=198.51.100.23 DST=192.0.2.5 ... SPT=50000 DPT=20 ...
```

The generic parser extracts `SRC`, `DST`, `SPT`, `DPT` and marks `BLOCK` lines as
failures. The port-scan rule counts distinct destination ports per source in a
300-second window and fires at 10 or more. Because the sample uses sequential
ports, it triggers cleanly.

This is also a lesson in evidence requirements: authentication logs do not carry
destination ports, so the port-scan rule correctly stays silent on them.

---

## 7. Running the whole pipeline

```bash
python main.py --db /tmp/walkthrough.db offline --directory sample_logs
python main.py --db /tmp/walkthrough.db alerts --severity CRITICAL
python main.py --db /tmp/walkthrough.db report --output /tmp/walkthrough.html
python main.py --db /tmp/walkthrough.db dashboard --port 8080
```

In the dashboard:

1. Open `/` to see counts and recent alerts.
2. Open `/alerts` and filter by severity.
3. Open an alert to read its explanation and evidence.
4. Change its status to `INVESTIGATING` and add a note.
5. Open `/events` and filter by the source IP to see the full timeline.
6. Open `/analytics` to see top IPs, users and formats.

This is the workflow a junior analyst would follow: alert -> evidence -> context
-> decision -> documentation.

---

## 8. Exercises

### Exercise 1: Raise the brute-force threshold

Edit `config/detection_rules.json`:

```json
"ssh_brute_force": { "threshold": 15 }
```

Re-run:

```bash
rm -f /tmp/ex1.db
python main.py --db /tmp/ex1.db offline --file sample_logs/linux/auth.log
```

With 12 failures, the SSH brute-force alert should disappear. The
success-after-failures alert should remain because its threshold is separate.
This demonstrates that detection and severity are configurable and independent.

### Exercise 2: Denylist an IP

Add `203.0.113.50` to `suspicious_ip.denylist` and re-run. You should get a
`suspicious_ip` denylist finding with severity HIGH (MEDIUM bumped by one level)
in addition to the SSH alert. This demonstrates IOC-based detection and severity
bumping.

### Exercise 3: Disable a rule

Set `"port_scan": { "enabled": false }` and re-run over `sample_logs`. The port
scan alert should disappear while other alerts remain. This demonstrates rule
isolation.

### Exercise 4: Add a web pattern

Add a pattern for a custom admin path to `web_attack.patterns.sensitive_files`,
for example `"(?i)(/internal/debug)"`. Add a matching line to a copy of
`apache_access.log` and confirm a `web_attack_sensitive_files` alert appears.

### Exercise 5: Explain an alert without running the tool

Given an alert with severity CRITICAL, rule `ssh_brute_force`, 30 failures,
threshold 10 and 4 distinct usernames, explain the escalation. Answer: 30 >= 3x10
gives +2 (HIGH -> CRITICAL after capping), and 4 distinct usernames would add
another level but severity is already capped. The explanation should state the
volume and username rationale.

### Exercise 6: Write a rule

Create a rule that alerts on more than 3 Linux `user_created` events in 10
minutes. Implement `evaluate`, add config defaults, register it, and write a test.
This exercises the extension points described in `docs/architecture.md`.

---

## 9. Verification checklist

- [ ] `pytest -q` passes (54 tests).
- [ ] `python main.py status` reports the expected platform and database.
- [ ] Offline analysis of `sample_logs` produces 99 events and about 26 alerts.
- [ ] `alerts --severity CRITICAL` shows the SSH brute-force and audit-cleared
      alerts.
- [ ] The report opens and contains overview, alerts and events.
- [ ] The dashboard loads and an alert status can be changed.
- [ ] Live mode lists sources and respects permissions.
- [ ] EVTX parsing works on this platform.

---

## 10. Glossary

| Term | Meaning |
| --- | --- |
| Event | A single normalized log record |
| Finding | A rule's raw conclusion about events |
| Alert | A persisted, scored, deduplicated finding |
| Rule | Logic that maps events to findings |
| Threshold | Minimum count to trigger |
| Window | Time span used for counting |
| Densest window | The busiest sub-window of a given length |
| Dedup key | Identifier used to suppress duplicate open alerts |
| Fingerprint | Hash used to suppress duplicate ingested events |
| Severity | Qualitative risk label, not a probability |
| False positive | An alert on legitimate activity |
| False negative | Malicious activity that was not detected |
| IOC | Indicator of compromise, such as a known-bad IP |
| TTP | Tactics, techniques and procedures of an attacker |
| EVTX | Windows binary event log format |
| Syslog | Unix logging format and protocol |
| Triage | Human review and prioritization of alerts |

---

## 11. Critical thinking

- **Detection is not prevention.** An alert means "look here", not "attack
  confirmed".
- **Context beats thresholds.** A single audit-log clear can matter more than
  hundreds of failed passwords.
- **Attackers can evade simple rules.** Changing timing, spreading sources, or
  using legitimate tools can avoid threshold and name-based detection.
- **Baselines reduce noise.** Knowing what is normal for your environment is more
  valuable than a large rule set.
- **Document decisions.** Status changes and notes are part of the investigation,
  not paperwork.
- **Respect privacy and law.** Logs can contain personal data. Access only what
  you are authorized to access, minimize retention, and follow your
  organization's policy.

---

## 12. Where to go next

- Read `docs/architecture.md` to see how to extend the pipeline.
- Read `docs/detection-rules.md` for tuning and rule-writing details.
- Read `docs/troubleshooting.md` when something does not work.
- Explore `tests/` to see expected behavior at the boundary of every rule.
