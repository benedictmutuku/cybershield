import sqlite3

import pytest

from api.database import get_recent_scans, get_stats, save_scan


def test_save_scan_and_get_stats(tmp_path) -> None:
    db_path = tmp_path / "nested" / "scans.db"

    scan_id = save_scan(
        "https://example.com",
        "url",
        0.12,
        "safe",
        "No suspicious indicators",
        db_path=db_path,
    )
    save_scan(
        "Your account is locked",
        "message",
        0.76,
        "suspicious",
        "Urgency language",
        db_path=db_path,
    )
    save_scan(
        "https://fake.example",
        "url",
        0.98,
        "phishing",
        "Known malicious domain",
        db_path=db_path,
    )

    assert scan_id == 1
    assert get_stats(db_path=db_path) == {
        "total_scans": 3,
        "phishing_count": 1,
        "suspicious_count": 1,
        "safe_count": 1,
    }


def test_get_recent_scans_returns_newest_first_and_honors_limit(tmp_path) -> None:
    db_path = tmp_path / "scans.db"
    save_scan("first", "message", 0.1, "safe", "", db_path=db_path)
    save_scan("second", "message", 0.5, "suspicious", "reason", db_path=db_path)

    recent = get_recent_scans(limit=1, db_path=db_path)

    assert len(recent) == 1
    assert recent[0]["input_text"] == "second"
    assert recent[0]["label"] == "suspicious"
    assert recent[0]["created_at"]


def test_empty_database_stats_are_zero(tmp_path) -> None:
    assert get_stats(db_path=tmp_path / "empty.db") == {
        "total_scans": 0,
        "phishing_count": 0,
        "suspicious_count": 0,
        "safe_count": 0,
    }


@pytest.mark.parametrize(
    ("input_type", "label"),
    [("email", "safe"), ("url", "malware")],
)
def test_rejects_invalid_input_type_and_label(
    tmp_path, input_type: str, label: str
) -> None:
    with pytest.raises(ValueError):
        save_scan("some input", input_type, 0.5, label, "", db_path=tmp_path / "x.db")


@pytest.mark.parametrize("limit", [0, -1])
def test_rejects_non_positive_limit(tmp_path, limit: int) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        get_recent_scans(limit, db_path=tmp_path / "x.db")


def test_schema_has_requested_columns(tmp_path) -> None:
    db_path = tmp_path / "scans.db"
    get_stats(db_path=db_path)

    with sqlite3.connect(db_path) as connection:
        columns = [
            row[1] for row in connection.execute("PRAGMA table_info(scans)")
        ]

    assert columns == [
        "id",
        "input_text",
        "input_type",
        "risk_score",
        "label",
        "reasons",
        "created_at",
    ]
