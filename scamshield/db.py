"""SQLite access: schema, per-thread connections, db.run (ADR 0002)."""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
import time
from pathlib import Path

MIN_SQLITE = (3, 35, 0)  # RETURNING in the job claim
SCHEMA = Path(__file__).with_name("schema.sql")
_local = threading.local()
_db_path: str | None = None
log = logging.getLogger(__name__)
SLOW_CALL_S = 2.0  # diagnostic: a call this long holds up every other writer (busy_timeout 15 s) ("database is locked")


def check_sqlite_version(version: tuple[int, ...] = sqlite3.sqlite_version_info) -> None:
    if tuple(version) < MIN_SQLITE:
        found = ".".join(map(str, version))
        raise RuntimeError(f"SQLite >= 3.35 required, found {found}")


def _connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init(path: str) -> None:
    """Create the data dir and apply schema.sql (idempotent); remember the path for db.run."""
    global _db_path
    check_sqlite_version()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = _connect(path)
    try:
        conn.executescript(SCHEMA.read_text(encoding="utf-8"))
        if "job_id" not in [row[1] for row in conn.execute("PRAGMA table_info(facts)")]:
            conn.execute(
                "ALTER TABLE facts ADD COLUMN job_id INTEGER"
            )  # databases created before facts carried the job id
        conn.execute("CREATE INDEX IF NOT EXISTS idx_facts_job ON facts(job_id)")
        for column in ("input_hash TEXT", "carried_from INTEGER"):  # ai_reviews created before the judge's carry-over
            if column.split()[0] not in [row[1] for row in conn.execute("PRAGMA table_info(ai_reviews)")]:
                conn.execute(f"ALTER TABLE ai_reviews ADD COLUMN {column}")
        for column in (
            "input_hash TEXT",
            "carried_from INTEGER",
            "fact_order TEXT",
        ):  # explanations created before the reuse of unchanged answers
            if column.split()[0] not in [row[1] for row in conn.execute("PRAGMA table_info(explanations)")]:
                conn.execute(f"ALTER TABLE explanations ADD COLUMN {column}")
        if "cursor" not in [row[1] for row in conn.execute("PRAGMA table_info(heartbeats)")]:
            conn.execute(
                "ALTER TABLE heartbeats ADD COLUMN cursor INTEGER"
            )  # CT cursor per cycle, so a killed cycle's tiles still count in M1
        if "created_at" not in [row[1] for row in conn.execute("PRAGMA table_info(jobs)")]:
            conn.execute(
                "ALTER TABLE jobs ADD COLUMN created_at TEXT"
            )  # ingest time; databases created before live mode
        conn.commit()
    finally:
        conn.close()
    _db_path = path


def _conn() -> sqlite3.Connection:
    if _db_path is None:
        raise RuntimeError("db.init() was not called")
    if getattr(_local, "path", None) != _db_path:
        _local.conn, _local.path = _connect(_db_path), _db_path
    return _local.conn


def _call(fn, *args):
    conn = _conn()
    started = time.monotonic()
    try:
        return fn(conn, *args)
    except BaseException:
        if conn.in_transaction:  # a failed call must not keep this pooled thread's write lock / old snapshot ("database is locked" everywhere)
            conn.rollback()
        raise
    finally:
        elapsed = time.monotonic() - started
        if elapsed > SLOW_CALL_S:
            log.warning(
                "slow db call %s.%s: %.1f s", getattr(fn, "__module__", "?"), getattr(fn, "__qualname__", fn), elapsed
            )


async def run(fn, *args):
    """Execute fn(conn, *args) in a worker thread with that thread's own connection."""
    return await asyncio.to_thread(_call, fn, *args)


NAME_BRAND_SOURCES = (
    "baseline",
    "brand_check",
    "ct_tiled",
    "feeds",
    "urlhaus",
    "lookalike",
    "nrd",
)  # intake `lookalike` facts derived from the domain name alone


def current_facts(conn: sqlite3.Connection, domain_id: int) -> list[sqlite3.Row]:
    """The domain's current facts: from its last finished check_domain job, plus facts without a job (intake evidence).
    A name-derived intake `lookalike` fact is superseded by the last check's own `lookalike` fact (brand rules changed since intake).
    Older checks stay in the table as history. The one place that defines "current" (card, scoring, graph)."""
    marks = ",".join("?" * len(NAME_BRAND_SOURCES))
    return conn.execute(
        f"""WITH last AS (SELECT j.id FROM jobs j JOIN domains d ON d.fqdn = j.target
             WHERE d.id = ? AND j.kind = 'check_domain' AND j.status IN ('done', 'partial') ORDER BY j.id DESC LIMIT 1)
           SELECT f.* FROM facts f WHERE f.domain_id = ? AND (f.job_id = (SELECT id FROM last) OR (f.job_id IS NULL
             AND NOT (f.type = 'lookalike' AND f.source IN ({marks})
                      AND EXISTS (SELECT 1 FROM facts g WHERE g.domain_id = f.domain_id AND g.type = 'lookalike' AND g.job_id = (SELECT id FROM last)))))
           ORDER BY f.id""",
        (domain_id, domain_id, *NAME_BRAND_SOURCES),
    ).fetchall()
