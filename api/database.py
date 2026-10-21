"""SQLite persistence for CyberShield scan results."""

from __future__ import annotations

import math
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import TypedDict

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cybershield.db"

_VALID_INPUT_TYPES = {"url", "message"}
_VALID_LABELS = {"safe", "suspicious", "phishing"}


class ScanRecord(TypedDict):
    id: int
    input_text: str
    input_type: str
    risk_score: float
    label: str
    reasons: str
    created_at: str


def _connect(db_path: Path | str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_text TEXT NOT NULL,
            input_type TEXT NOT NULL CHECK (input_type IN ('url', 'message')),
            risk_score REAL NOT NULL,
            label TEXT NOT NULL CHECK (label IN ('safe', 'suspicious', 'phishing')),
            reasons TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    return connection


def save_scan(
    input_text: str,
    input_type: str,
    risk_score: float,
    label: str,
    reasons: str,
    *,
    db_path: Path | str = DB_PATH,
) -> int:
    """Save a scan and return its generated ID."""
    if not isinstance(input_text, str) or not input_text.strip():
        raise ValueError("input_text must be a non-empty string")
    if input_type not in _VALID_INPUT_TYPES:
        raise ValueError("input_type must be 'url' or 'message'")
    if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
        raise TypeError("risk_score must be a number")
    if not math.isfinite(risk_score):
        raise ValueError("risk_score must be finite")
    if label not in _VALID_LABELS:
        raise ValueError("label must be 'safe', 'suspicious', or 'phishing'")
    if not isinstance(reasons, str):
        raise TypeError("reasons must be a string")

    with closing(_connect(db_path)) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (input_text, input_type, risk_score, label, reasons)
                VALUES (?, ?, ?, ?, ?)
                """,
                (input_text, input_type, risk_score, label, reasons),
            )
            return int(cursor.lastrowid)


def get_recent_scans(
    limit: int = 10,
    *,
    db_path: Path | str = DB_PATH,
) -> list[ScanRecord]:
    """Return the most recent scans, newest first."""
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")
    if limit < 1:
        raise ValueError("limit must be at least 1")

    with closing(_connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT id, input_text, input_type, risk_score, label, reasons, created_at
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [ScanRecord(**dict(row)) for row in rows]


def get_stats(*, db_path: Path | str = DB_PATH) -> dict[str, int]:
    """Return total and per-label scan counts."""
    with closing(_connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total_scans,
                COALESCE(SUM(label = 'phishing'), 0) AS phishing_count,
                COALESCE(SUM(label = 'suspicious'), 0) AS suspicious_count,
                COALESCE(SUM(label = 'safe'), 0) AS safe_count
            FROM scans
            """
        ).fetchone()
    return {key: int(row[key]) for key in row.keys()}
