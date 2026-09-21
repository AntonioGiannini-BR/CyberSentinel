from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    report_path TEXT NOT NULL,
    total_events INTEGER NOT NULL,
    failed_logins INTEGER NOT NULL,
    successful_logins INTEGER NOT NULL,
    suspicious_ips INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    result_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analyses_created_at
ON analyses(created_at DESC);
"""


def connect(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row

    return connection


def init_db(db_path: Path):
    with connect(db_path) as connection:
        connection.executescript(SCHEMA)
        connection.commit()


def save_analysis(
    db_path: Path,
    filename: str,
    stored_path: Path,
    report_path: Path,
    result: dict[str, Any],
) -> int:
    summary = result.get("summary", {})
    created_at = datetime.now(timezone.utc).isoformat()

    with connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO analyses (
                filename,
                stored_path,
                report_path,
                total_events,
                failed_logins,
                successful_logins,
                suspicious_ips,
                created_at,
                result_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                filename,
                str(stored_path),
                str(report_path),
                int(summary.get("total_events", 0)),
                int(summary.get("failed_logins", 0)),
                int(summary.get("successful_logins", 0)),
                len(result.get("suspicious_ips", [])),
                created_at,
                json.dumps(result, ensure_ascii=False),
            ),
        )

        connection.commit()
        return int(cursor.lastrowid)


def list_analyses(
    db_path: Path,
    limit: int = 50,
    query: str = "",
):
    with connect(db_path) as connection:
        if query:
            return list(
                connection.execute(
                    """
                    SELECT *
                    FROM analyses
                    WHERE filename LIKE ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (f"%{query}%", limit),
                )
            )

        return list(
            connection.execute(
                """
                SELECT *
                FROM analyses
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
        )


def get_analysis(db_path: Path, analysis_id: int):
    with connect(db_path) as connection:
        return connection.execute(
            "SELECT * FROM analyses WHERE id = ?",
            (analysis_id,),
        ).fetchone()


def delete_analysis(db_path: Path, analysis_id: int) -> bool:
    with connect(db_path) as connection:
        cursor = connection.execute(
            "DELETE FROM analyses WHERE id = ?",
            (analysis_id,),
        )
        connection.commit()

        return cursor.rowcount > 0


def dashboard_stats(db_path: Path) -> dict[str, Any]:
    rows = list_analyses(db_path, limit=500)

    totals = {
        "analyses": len(rows),
        "events": 0,
        "failed": 0,
        "success": 0,
        "alerts": 0,
    }

    risk = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    categories = {
        "Brute force": 0,
        "Falhas de login": 0,
        "Usuários alvo": 0,
        "IPs únicos": 0,
    }

    days = {}

    for row in rows:
        totals["events"] += row["total_events"]
        totals["failed"] += row["failed_logins"]
        totals["success"] += row["successful_logins"]
        totals["alerts"] += row["suspicious_ips"]

        day = row["created_at"][:10]

        day_data = days.setdefault(
            day,
            {
                "analyses": 0,
                "alerts": 0,
            },
        )

        day_data["analyses"] += 1
        day_data["alerts"] += row["suspicious_ips"]

        try:
            result = json.loads(row["result_json"])
        except (json.JSONDecodeError, TypeError):
            result = {}

        suspicious_ips = result.get("suspicious_ips", [])

        for item in suspicious_ips:
            risk_level = item.get("risk", "MEDIUM")

            if risk_level not in risk:
                risk_level = "MEDIUM"

            risk[risk_level] += 1

        categories["Brute force"] += len(suspicious_ips)
        categories["Falhas de login"] += row["failed_logins"]
        categories["Usuários alvo"] += len(
            result.get("targeted_users", [])
        )
        categories["IPs únicos"] += (
            result.get("summary", {}).get("unique_ips", 0)
        )

    timeline = [
        {
            "day": day,
            "analyses": values["analyses"],
            "alerts": values["alerts"],
        }
        for day, values in sorted(days.items())[-7:]
    ]

    denominator = max(totals["events"], 1)

    risk_score = min(
        100,
        round(
            (totals["failed"] / denominator) * 55
            + min(totals["alerts"] * 8, 45)
        ),
    )

    return {
        "totals": totals,
        "risk": risk,
        "categories": categories,
        "timeline": timeline,
        "risk_score": risk_score,
    }