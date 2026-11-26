"""Security hardening tests: uploads, path traversal, SQL injection safety."""

from __future__ import annotations

import pytest

from siem.database.db_manager import DBManager
from siem.utils.file_validator import (
    ValidationError,
    check_upload_size,
    safe_join,
    validate_read_path,
    validate_upload_extension,
    validate_upload_name,
)


def test_upload_name_strips_path():
    assert validate_upload_name("../../etc/passwd") == "passwd"
    assert validate_upload_name("C:\\Windows\\evil.log") == "evil.log"
    with pytest.raises(ValidationError):
        validate_upload_name("..")
    with pytest.raises(ValidationError):
        validate_upload_name("")


def test_safe_join_blocks_traversal(tmp_path):
    target = safe_join(tmp_path, "log.txt")
    assert target.parent == tmp_path.resolve()
    # Even though validate_upload_name strips directories, ensure the result
    # cannot escape the base directory.
    assert str(safe_join(tmp_path, "../../log.txt")).startswith(str(tmp_path.resolve()))


def test_upload_extension_and_size():
    validate_upload_extension("auth.log")
    validate_upload_extension("security.evtx")
    with pytest.raises(ValidationError):
        validate_upload_extension("malware.exe")
    with pytest.raises(ValidationError):
        check_upload_size(0)
    with pytest.raises(ValidationError):
        check_upload_size(10 * 1024 * 1024 * 1024)


def test_validate_read_path_missing():
    with pytest.raises(ValidationError):
        validate_read_path("/definitely/not/here.log")


def test_sql_injection_input_is_parameterized(tmp_db):
    from siem.models import Event

    event = Event(
        timestamp="2024-01-15T10:00:00+00:00",
        raw_message="normal",
        source_ip="1.2.3.4",
        log_format="generic",
    )
    tmp_db.insert_events([event])
    malicious = "'; DROP TABLE events; --"
    results = tmp_db.get_events(search=malicious)
    assert results == []
    # Table must still exist.
    assert tmp_db.count_events() == 1
    # Filtering by a malicious IP value must not break the query.
    assert tmp_db.get_events(source_ip=malicious) == []
