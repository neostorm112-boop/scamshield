"""A function that fails inside db.run must not leave its thread's connection holding the write lock (database is locked everywhere)."""

import asyncio
import sqlite3

import pytest

from scamshield import db


def _insert_then_fail(conn):
    conn.execute("INSERT INTO feed_meta (key, value) VALUES ('t', '1')")
    raise RuntimeError("boom")


def test_failed_call_releases_write_lock(tmp_path):
    path = str(tmp_path / "t.db")
    db.init(path)
    with pytest.raises(RuntimeError):
        asyncio.run(db.run(_insert_then_fail))
    other = sqlite3.connect(path, timeout=0.2)
    other.execute(
        "INSERT INTO feed_meta (key, value) VALUES ('u', '1')"
    )  # raises "database is locked" if the failed call kept its transaction
    other.commit()
    assert [r[0] for r in other.execute("SELECT key FROM feed_meta")] == ["u"]  # the failed call's row is rolled back
