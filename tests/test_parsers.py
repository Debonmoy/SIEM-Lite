"""Parser tests: Linux, web, Windows, EVTX, malformed input, timestamps."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from siem.parsers.apache_parser import ApacheAccessParser, ApacheErrorParser
from siem.parsers.auth_parser import AuthParser
from siem.parsers.common import (
    parse_apache_timestamp,
    parse_syslog_timestamp,
    parse_windows_time,
)
from siem.parsers.generic_parser import GenericParser
from siem.parsers.nginx_parser import NginxAccessParser, NginxErrorParser
from siem.parsers.registry import ParserRegistry
from siem.parsers.ssh_parser import SSHParser
from siem.parsers.windows_csv_parser import WindowsCsvParser
from siem.parsers.windows_json_parser import WindowsJsonParser
from siem.parsers.windows_xml_parser import WindowsXmlParser, events_from_xml_text


def test_auth_parser_failed_and_accepted():
    parser = AuthParser()
    failed = parser.parse_line(
        "Jan 15 10:23:45 web01 sshd[1234]: Failed password for invalid user admin "
        "from 192.168.1.50 port 54321 ssh2"
    )
    assert failed is not None
    assert failed.auth_result == "failure"
    assert failed.username == "admin"
    assert failed.source_ip == "192.168.1.50"
    assert failed.source_port == 54321
    assert failed.host == "web01"

    accepted = parser.parse_line(
        "Jan 15 10:23:47 web01 sshd[1234]: Accepted password for root "
        "from 10.0.0.5 port 2222 ssh2"
    )
    assert accepted.auth_result == "success"
    assert accepted.username == "root"
    assert accepted.source_ip == "10.0.0.5"


def test_auth_parser_pam_and_account_events():
    parser = AuthParser()
    pam = parser.parse_line(
        "Jan 15 10:26:00 web01 pam_unix(sshd:auth): authentication failure; "
        "logname= uid=0 euid=0 tty=ssh ruser= rhost=8.8.8.8 user=admin"
    )
    assert pam.auth_result == "failure"
    assert pam.username == "admin"
    assert pam.source_ip == "8.8.8.8"
    assert pam.event_type == "ssh_login_failed"

    useradd = parser.parse_line(
        "Jan 15 10:25:00 web01 useradd[999]: new user: name=bob, UID=1001, GID=1001"
    )
    assert useradd.event_type == "user_created"
    assert useradd.username == "bob"

    sudo = parser.parse_line(
        "Jan 15 10:24:00 web01 sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/bin/ls"
    )
    assert sudo.event_type == "sudo_command"
    assert sudo.username == "alice"
    assert sudo.extra["command"] == "/bin/ls"


def test_ssh_parser_only_sshd():
    parser = SSHParser()
    event = parser.parse_line(
        "Jan 15 10:23:45 web01 sshd[1234]: Failed password for admin from 1.2.3.4 port 1234 ssh2"
    )
    assert event is not None
    assert event.log_format == "ssh"
    assert event.auth_result == "failure"
    assert parser.parse_line(
        "Jan 15 10:24:00 web01 sudo: alice : COMMAND=/bin/ls"
    ) is None


def test_apache_access_and_error():
    access = ApacheAccessParser().parse_line(
        '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /x?q=1 HTTP/1.0" '
        '200 2326 "http://ref/" "Mozilla/4.08"'
    )
    assert access.source_ip == "127.0.0.1"
    assert access.username == "frank"
    assert access.http_method == "GET"
    assert access.request_path == "/x?q=1"
    assert access.http_status == 200
    assert access.user_agent == "Mozilla/4.08"

    error = ApacheErrorParser().parse_line(
        "[Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] "
        "client denied by server configuration: /export/home"
    )
    assert error.source_ip == "127.0.0.1"
    assert error.extra["level"] == "error"


def test_nginx_access_and_error():
    access = NginxAccessParser().parse_line(
        '10.0.0.9 - - [10/Oct/2000:13:55:36 +0000] "GET /a HTTP/1.1" 404 12 "-" "curl"'
    )
    assert access.log_format == "nginx_access"
    assert access.http_status == 404

    error = NginxErrorParser().parse_line(
        '2024/01/15 10:23:45 [error] 1234#1234: *5 access forbidden by rule, '
        'client: 5.6.7.8, server: example.com, request: "GET /admin HTTP/1.1"'
    )
    assert error.source_ip == "5.6.7.8"
    assert error.request_path == "/admin"


def test_windows_xml_parsing():
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><Provider Name=\"Microsoft-Windows-Security-Auditing\"/>"
        "<EventID>4625</EventID>"
        '<TimeCreated SystemTime="2024-01-15T10:23:45.1234567Z"/>'
        "<Computer>DC01</Computer><Channel>Security</Channel></System>"
        '<EventData><Data Name="TargetUserName">admin</Data>'
        '<Data Name="IpAddress">1.2.3.4</Data>'
        '<Data Name="IpPort">5555</Data></EventData></Event>'
    )
    events, errors = events_from_xml_text(xml)
    assert not errors and len(events) == 1
    event = events[0]
    assert event.event_code == "4625"
    assert event.event_type == "logon_failure"
    assert event.auth_result == "failure"
    assert event.username == "admin"
    assert event.source_ip == "1.2.3.4"
    assert event.source_port == 5555
    assert event.host == "DC01"
    assert event.os_source == "windows"


def test_windows_xml_malformed_and_empty(tmp_path: Path):
    bad = tmp_path / "bad.xml"
    bad.write_text("<Event><System><EventID>4625", encoding="utf-8")
    result = WindowsXmlParser().parse_file(bad)
    assert result.events == []
    assert result.errors

    empty = tmp_path / "empty.xml"
    empty.write_text("", encoding="utf-8")
    result = WindowsXmlParser().parse_file(empty)
    assert result.events == []
    assert any("empty" in e.lower() for e in result.errors)


def test_windows_csv_parsing(tmp_path: Path):
    path = tmp_path / "events.csv"
    path.write_text(
        "TimeCreated,EventID,Computer,TargetUserName,IpAddress\n"
        "2024-01-15T10:23:45Z,4625,DC01,admin,1.2.3.4\n",
        encoding="utf-8",
    )
    result = WindowsCsvParser().parse_file(path)
    assert len(result.events) == 1
    event = result.events[0]
    assert event.event_code == "4625"
    assert event.username == "admin"
    assert event.source_ip == "1.2.3.4"
    assert event.timestamp.startswith("2024-01-15T10:23:45")


def test_windows_json_array_and_ndjson(tmp_path: Path):
    obj = {
        "EventID": 4624,
        "TimeCreated": "2024-01-15T10:23:45Z",
        "Computer": "DC01",
        "EventData": {"TargetUserName": "alice", "IpAddress": "10.0.0.5"},
    }
    array_file = tmp_path / "events.json"
    array_file.write_text(json.dumps([obj, obj]), encoding="utf-8")
    result = WindowsJsonParser().parse_file(array_file)
    assert len(result.events) == 2
    assert result.events[0].username == "alice"

    ndjson = tmp_path / "events.ndjson"
    ndjson.write_text(json.dumps(obj) + "\n" + "not-json\n" + json.dumps(obj) + "\n")
    result = WindowsJsonParser().parse_file(ndjson)
    assert len(result.events) == 2
    assert result.errors


def test_evtx_parsing(sample_dir: Path):
    pytest.importorskip("Evtx")
    path = sample_dir / "windows" / "new-user-security.evtx"
    if not path.exists():
        pytest.skip("EVTX sample not present")
    registry = ParserRegistry()
    result = registry.parse_file(path)
    assert result.parser_name == "evtx"
    assert len(result.events) == 4
    codes = {event.event_code for event in result.events}
    assert {"4720", "4728", "4732"} <= codes
    assert all(event.os_source == "windows" for event in result.events)


def test_registry_auto_detection(tmp_path: Path):
    registry = ParserRegistry()
    samples = {
        "auth.log": "Jan 15 10:23:45 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n",
        "access.log": '1.2.3.4 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.0" 200 1 "-" "x"\n',
        "nginx_error.log": "2024/01/15 10:23:45 [error] 1#1: *5 client: 1.2.3.4, request: \"GET / HTTP/1.1\"\n",
    }
    expected = {"auth.log": "ssh", "access.log": "apache_access", "nginx_error.log": "nginx_error"}
    for name, content in samples.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        assert registry.detect_format_name(path) == expected[name]


def test_generic_firewall_extraction():
    event = GenericParser().parse_line(
        "2024-01-15T10:00:00Z fw kernel: [UFW BLOCK] IN=eth0 SRC=9.9.9.9 "
        "DST=10.0.0.1 SPT=40000 DPT=22 PROTO=TCP"
    )
    assert event.event_type == "firewall_event"
    assert event.source_ip == "9.9.9.9"
    assert event.destination_ip == "10.0.0.1"
    assert event.destination_port == 22
    assert event.auth_result == "failure"


def test_timestamp_formats():
    assert parse_syslog_timestamp(
        "Jan 15 10:23:45", now=datetime(2024, 6, 1, tzinfo=timezone.utc)
    ).startswith("2024-01-15T10:23:45")
    assert parse_apache_timestamp("10/Oct/2000:13:55:36 -0700").startswith(
        "2000-10-10T13:55:36"
    )
    parsed = parse_windows_time("2024-01-15T10:23:45.1234567Z")
    assert parsed == "2024-01-15T10:23:45.123456+00:00"
    assert parse_windows_time("not-a-date") is None


def test_empty_and_malformed_text_file(tmp_path: Path):
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    result = AuthParser().parse_file(empty)
    assert result.events == []
    assert result.errors

    mixed = tmp_path / "mixed.log"
    mixed.write_text(
        "garbage line without syslog prefix\n"
        "Jan 15 10:23:45 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n",
        encoding="utf-8",
    )
    result = AuthParser().parse_file(mixed)
    assert len(result.events) == 1
    assert result.events[0].source_ip == "1.2.3.4"


def test_json_not_misdetected_as_csv(tmp_path: Path):
    path = tmp_path / "events.json"
    path.write_text(
        json.dumps({"EventID": 4624, "TimeCreated": "2024-01-15T10:00:00Z"}),
        encoding="utf-8",
    )
    assert ParserRegistry().detect_format_name(path) == "windows_json"
