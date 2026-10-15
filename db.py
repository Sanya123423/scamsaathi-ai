"""
ScamSaathi - Lightweight SQLite Telemetry & Alert History Store
Zero-setup, thread-safe, local database for cybersecurity telemetry.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager

DB_FILE = Path(__file__).resolve().parent / "scamsaathi.db"

@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    """Initializes the SQLite schema."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                message_snippet TEXT,
                target_url TEXT,
                threat_type TEXT,
                risk_score INTEGER,
                severity TEXT,
                categories TEXT,
                indicators_count INTEGER,
                details_json TEXT
            )
        """)
        conn.commit()

def record_scan(assessment: dict, target_url: str = '') -> int:
    """Inserts a completed threat assessment record into SQLite."""
    init_db()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    snippet = (assessment.get('redacted_message') or target_url or 'Empty Content')[:100]
    
    categories = assessment.get('threat_categories', [])
    categories_str = ", ".join(categories) if isinstance(categories, list) else str(categories)
    
    indicators = assessment.get('detected_indicators', [])
    ind_count = len(indicators) if isinstance(indicators, list) else 0

    with get_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO scans (
                timestamp, message_snippet, target_url, threat_type,
                risk_score, severity, categories, indicators_count, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            now_str,
            snippet,
            target_url,
            assessment.get('threat_type', 'Scan'),
            int(assessment.get('risk_score', 0)),
            assessment.get('severity', 'Low'),
            categories_str,
            ind_count,
            json.dumps(assessment)
        ))
        conn.commit()
        return cursor.lastrowid

def get_telemetry_stats() -> dict:
    """Retrieves high-level telemetry stats for the dashboard cards."""
    init_db()
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high_crit = conn.execute("SELECT COUNT(*) FROM scans WHERE severity IN ('High', 'Critical')").fetchone()[0]
        safe = conn.execute("SELECT COUNT(*) FROM scans WHERE severity = 'Low'").fetchone()[0]
        suspicious_urls = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE target_url != '' OR categories LIKE '%URL Forensics%'"
        ).fetchone()[0]

    return {
        'total_scans': total,
        'high_critical_count': high_crit,
        'safe_scans_count': safe,
        'suspicious_urls_count': suspicious_urls
    }

def get_recent_alerts(limit: int = 50, search: str = '') -> list[dict]:
    """Fetches recent scan records with optional keyword filtering."""
    init_db()
    with get_connection() as conn:
        if search and search.strip():
            term = f"%{search.strip()}%"
            rows = conn.execute("""
                SELECT id, timestamp, message_snippet, target_url, threat_type,
                       risk_score, severity, categories, indicators_count, details_json
                FROM scans
                WHERE message_snippet LIKE ? OR target_url LIKE ? OR categories LIKE ? OR threat_type LIKE ?
                ORDER BY id DESC
                LIMIT ?
            """, (term, term, term, term, limit)).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, timestamp, message_snippet, target_url, threat_type,
                       risk_score, severity, categories, indicators_count, details_json
                FROM scans
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()

    result = []
    for r in rows:
        item = dict(r)
        if item.get('details_json'):
            try:
                item['details'] = json.loads(item['details_json'])
            except Exception:
                item['details'] = {}
        result.append(item)
    return result

def get_alert_by_id(alert_id: int) -> dict:
    """Retrieves deep analysis forensic details for a single record."""
    init_db()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return None
        res = dict(row)
        if res.get('details_json'):
            try:
                res['details'] = json.loads(res['details_json'])
            except Exception:
                res['details'] = {}
        return res

def clear_all_scans():
    """Resets the scans database for a fresh demonstration run."""
    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()

