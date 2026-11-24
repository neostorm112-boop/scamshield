"""Local append-only analyst feedback."""

from __future__ import annotations

from datetime import UTC, datetime

from scamshield import db


async def save(domain_id: int, verdict: str, reason: str, analyst: str | None) -> bool:
    if verdict not in {"scam", "legit", "unclear"} or not reason.strip():
        return False

    def insert(conn):
        conn.execute(
            "INSERT INTO feedback (domain_id, verdict, reason, analyst, created_at) VALUES (?, ?, ?, ?, ?)",
            (domain_id, verdict, reason.strip(), analyst, datetime.now(UTC).isoformat().replace("+00:00", "Z")),
        )
        conn.commit()

    await db.run(insert)
    return True
