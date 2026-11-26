# Sample logs

All files in this directory are provided so the tool can be demonstrated and
tested without touching real systems. Most are **synthetic** and contain only
documentation-range IP addresses (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) and invented host/user names.

Do not treat these files as evidence of real activity.

## Linux samples (`linux/`)

| File | Format | Purpose | Expected detections |
| --- | --- | --- | --- |
| `auth.log` | Linux auth / SSH | 12 failed SSH logins from one IP, a later success, sudo, user creation, PAM failure, public-key login | `ssh_brute_force` (CRITICAL after escalation), `success_after_failures` |
| `apache_access.log` | Apache combined access | Normal traffic plus SQL injection, directory traversal, XSS, sensitive-file requests, and a 401/403 burst | `web_attack_sql_injection`, `web_attack_directory_traversal`, `web_attack_xss`, `web_attack_sensitive_files`, `web_auth_failures` |
| `nginx_error.log` | Nginx error | Denied admin access and a sensitive-file request | `web_attack_sensitive_files` |
| `firewall.log` | Netfilter/UFW key-value | Sequential blocked destination ports from one source | `port_scan`, `suspicious_ip` |

`auth.log` timestamps are deliberately close together (09:50:00–09:50:11) so
the default 10-failures-in-300-seconds rule triggers.

## Windows samples (`windows/`)

| File | Format | Notes |
| --- | --- | --- |
| `security_events.json` | Windows Event JSON array | Failed logons (4625), success (4624), lockout (4740), audit log cleared (1102), account creation (4720), group change (4728), explicit credentials (4648), special privileges (4672), service installation (4697), process creation (4688) |
| `security_events.xml` | Windows Event XML | A small 4625/4624/4720 export |
| `security_events.csv` | Windows Event CSV | A small 4625/4624/4720 export |
| `new-user-security.evtx` | Binary EVTX | Real EVTX container with 4720/4728/4732 events |

The JSON/XML/CSV files are synthetic. The EVTX file is a public test fixture.

### EVTX attribution

`new-user-security.evtx` was downloaded from the sample set of the
[`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) project, which is
distributed under the MIT License. It is used here solely to verify that the
EVTX parser works on Linux/WSL without a Windows host. All credit for the
fixture belongs to that project.

- Upstream: https://github.com/omerbenamram/evtx
- Raw file: https://raw.githubusercontent.com/omerbenamram/evtx/master/samples/new-user-security.evtx
- License: MIT

If you redistribute this repository, keep this attribution with the fixture.

## Expected aggregate result

Running offline analysis over the whole directory with the default rules
produces approximately:

```
Events parsed      : 99
New events stored  : 99
Findings           : 26
Alerts generated   : 26
```

Exact alert counts can change if you edit `config/detection_rules.json`.
