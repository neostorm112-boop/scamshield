import asyncio
import sqlite3

from scamshield import db


def test_save_feedback_is_append_only(tmp_path):
    from scamshield import feedback

    db.init(str(tmp_path / "scamshield.db"))
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by) VALUES ('example.com', 'example.com', '2026-11-19T00:00:00Z', 'manual')"
    )
    conn.commit()
    assert asyncio.run(feedback.save(1, "scam", "credential collection", None)) is True
    assert sqlite3.connect(tmp_path / "scamshield.db").execute("SELECT verdict, reason FROM feedback").fetchone() == (
        "scam",
        "credential collection",
    )
