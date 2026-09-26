"""
SQLite Database Layer for Phishing URL Detection System.
Provides safe parameterized queries, search, filtering, and stats aggregation.
"""

import os
import json
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "scans.db")


def get_db_connection():
    """Returns a connection to the SQLite database with dictionary-like row access."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the scans database schema."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            domain TEXT,
            result TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            confidence REAL NOT NULL,
            features_json TEXT,
            reasons_json TEXT,
            scan_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def insert_scan(url: str, domain: str, result: str, risk_score: int,
                risk_level: str, confidence: float, features: dict, reasons: list) -> int:
    """Inserts a new scan result record into the database."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO scans (url, domain, result, risk_score, risk_level, confidence, features_json, reasons_json, scan_timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        domain,
        result,
        int(risk_score),
        risk_level,
        float(confidence),
        json.dumps(features),
        json.dumps(reasons),
        now_str
    ))
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_scan_by_id(scan_id: int):
    """Retrieves a single scan record by ID."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    item = dict(row)
    item["features"] = json.loads(item["features_json"]) if item["features_json"] else {}
    item["reasons"] = json.loads(item["reasons_json"]) if item["reasons_json"] else []
    return item


def get_recent_scans(limit: int = 10):
    """Retrieves the most recent N scans for dashboard display."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, url, domain, result, risk_score, risk_level, confidence, scan_timestamp
        FROM scans
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_scans(query: str = None, filter_type: str = None, limit: int = 100, offset: int = 0):
    """Retrieves scans with optional search query and category filtering."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    sql = "SELECT id, url, domain, result, risk_score, risk_level, confidence, scan_timestamp, features_json, reasons_json FROM scans WHERE 1=1"
    params = []

    if query:
        sql += " AND (url LIKE ? OR domain LIKE ?)"
        term = f"%{query.strip()}%"
        params.extend([term, term])

    if filter_type:
        filter_type = filter_type.strip().lower()
        if filter_type == "phishing":
            sql += " AND result = 'Likely Phishing'"
        elif filter_type == "safe":
            sql += " AND result = 'Likely Safe'"
        elif filter_type in ["high", "medium", "low"]:
            sql += " AND LOWER(risk_level) = ?"
            params.append(filter_type)

    # Get total matching count
    count_sql = f"SELECT COUNT(*) FROM ({sql})"
    cursor.execute(count_sql, params)
    total_count = cursor.fetchone()[0]

    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(sql, params)
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        item = dict(r)
        item["features"] = json.loads(item["features_json"]) if item.get("features_json") else {}
        item["reasons"] = json.loads(item["reasons_json"]) if item.get("reasons_json") else []
        results.append(item)

    return results, total_count


def delete_scan(scan_id: int) -> bool:
    """Deletes an individual scan by ID."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def clear_all_scans() -> bool:
    """Deletes all scan records."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return True


def get_dashboard_stats():
    """Aggregates metrics for the cybersecurity dashboard."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result = 'Likely Phishing'")
    phishing_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result = 'Likely Safe'")
    safe_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'HIGH'")
    high_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'MEDIUM'")
    medium_risk_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'LOW'")
    low_risk_count = cursor.fetchone()[0]

    # Recent scan trend (last 7 recorded days/records)
    cursor.execute("""
        SELECT SUBSTR(scan_timestamp, 1, 10) as scan_date,
               SUM(CASE WHEN result = 'Likely Phishing' THEN 1 ELSE 0 END) as phish,
               SUM(CASE WHEN result = 'Likely Safe' THEN 1 ELSE 0 END) as safe
        FROM scans
        GROUP BY scan_date
        ORDER BY scan_date ASC
        LIMIT 7
    """)
    trend_rows = cursor.fetchall()
    conn.close()

    trend = [
        {"date": r["scan_date"], "phishing": r["phish"], "safe": r["safe"]}
        for r in trend_rows
    ]

    return {
        "total_scans": total_scans,
        "phishing_count": phishing_count,
        "safe_count": safe_count,
        "high_risk_count": high_risk_count,
        "medium_risk_count": medium_risk_count,
        "low_risk_count": low_risk_count,
        "trend": trend,
    }
