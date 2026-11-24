"""The single entry point for domains: upsert, evidence facts and the check job (manual checks and CT)."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

from scamshield import db, worker
from scamshield.contracts import Candidate, Fact
from scamshield.enrich.lookalike import fact_value
from scamshield.netsafe import registrable_of

BASELINE_PRIORITY = -10  # first feed load: hundreds of old entries must not push ahead of live finds
GENERIC_PRIORITY = -1  # brandless CT names are checked after the UAE brand hits


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _submit(
    conn: sqlite3.Connection,
    fqdn: str,
    found_by: str,
    evidence: list[Fact],
    priority: int,
    brand: str | None = None,
    seen_at: str | None = None,
    data_mode: str = "LIVE",
    recheck_s: int | None = None,
) -> None:
    registrable = registrable_of(fqdn)
    if not registrable:
        return
    seen_at = seen_at or _now()
    new_cert = found_by == "ct_tiled" and worker.has_new_certificate(conn, fqdn, seen_at)
    conn.execute(
        """INSERT INTO domains (fqdn, registrable, brand_id, first_seen_at, found_by, last_seen_at, data_mode)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(fqdn) DO UPDATE SET last_seen_at=excluded.last_seen_at""",
        (fqdn, registrable, brand, seen_at, found_by, seen_at, data_mode),
    )
    domain_id = conn.execute("SELECT id FROM domains WHERE fqdn = ?", (fqdn,)).fetchone()[0]
    for fact in evidence:
        value_json = json.dumps(fact.value)
        if conn.execute(
            "SELECT 1 FROM facts WHERE domain_id = ? AND type = ? AND value_json = ? AND source = ?",
            (domain_id, fact.type, value_json, fact.source),
        ).fetchone():
            continue  # same evidence seen again: only domains.last_seen_at moves
        conn.execute(
            """INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, error, data_mode, raw_ref)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                domain_id,
                fact.type,
                value_json,
                fact.source,
                fact.observed_at,
                fact.fetched_at,
                fact.status,
                fact.error,
                fact.data_mode,
                fact.raw_ref,
            ),
        )
    # CT re-sightings share one key per re-check window; manual checks keep the per-minute key
    bucket = f"ct:{int(datetime.fromisoformat(seen_at).timestamp()) // recheck_s}" if recheck_s else seen_at[:16]
    if new_cert:
        bucket = f"cert:{seen_at}"  # a new certificate re-assesses at once, even inside the re-check window
    worker.enqueue_in(conn, "check_domain", fqdn, {"found_by": found_by}, f"check_domain:{fqdn}:{bucket}", priority)


async def submit(fqdn: str, found_by: str, evidence: list[Fact], priority: int) -> None:
    def run(conn):
        _submit(conn, fqdn, found_by, evidence, priority)
        conn.commit()

    await db.run(run)


def _store(
    conn: sqlite3.Connection, candidates: list[Candidate], connector: str, cursor: str | None, recheck_s: int
) -> None:
    for candidate in candidates:
        brand = candidate.metadata.get("brand")
        evidence = []
        if brand or candidate.metadata.get("method"):
            value = fact_value(candidate.metadata)
            evidence = [
                Fact(
                    "lookalike",
                    value,
                    candidate.source,
                    candidate.observed_at,
                    candidate.observed_at,
                    "ok",
                    data_mode=candidate.data_mode,
                )
            ]
        evidence += candidate.metadata.get("facts", [])  # source-specific facts, e.g. "listed in URLhaus"
        _submit(
            conn,
            candidate.value,
            candidate.source,
            evidence,
            BASELINE_PRIORITY
            if candidate.source == "baseline"
            else GENERIC_PRIORITY
            if candidate.metadata.get("mode") == "generic"
            else 0,
            brand,
            candidate.observed_at,
            candidate.data_mode,
            recheck_s,
        )
        if candidate.metadata.get("url"):
            conn.execute(
                """INSERT OR IGNORE INTO urls (domain_id, url, first_seen_at, source, data_mode)
                            SELECT id, ?, ?, ?, ? FROM domains WHERE fqdn = ?""",
                (
                    candidate.metadata["url"],
                    candidate.observed_at or _now(),
                    candidate.source,
                    candidate.data_mode,
                    candidate.value,
                ),
            )
    if cursor is not None:
        conn.execute(
            "INSERT INTO cursors (connector, cursor, updated_at) VALUES (?, ?, datetime('now')) "
            "ON CONFLICT(connector) DO UPDATE SET cursor=excluded.cursor, updated_at=excluded.updated_at",
            (connector, cursor),
        )
    conn.commit()


async def store_candidates(candidates: list[Candidate], connector: str, cursor: str | None, recheck_s: int) -> None:
    await db.run(_store, candidates, connector, cursor, recheck_s)
