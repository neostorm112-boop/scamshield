"""Durable SQLite job queue primitives used by the background worker."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from scamshield import db, explain, graph, runtime, triage_ai
from scamshield.contracts import FactRow, Verdict
from scamshield.enrich import asn, certspotter, dns, feed_match, lookalike, rdap
from scamshield.scoring import assess


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _recover(conn) -> None:
    # attempts was already incremented at claim, so an interrupted run counts as an attempt
    conn.execute("""UPDATE jobs SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
                    error = CASE WHEN attempts >= max_attempts THEN 'interrupted' ELSE error END,
                    started_at = NULL WHERE status = 'running'""")
    conn.commit()


def _claim(conn):
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    row = conn.execute(
        """UPDATE jobs SET status = 'running', started_at = ?, attempts = attempts + 1
           WHERE id = (SELECT id FROM jobs WHERE status = 'queued'
                       AND (run_after IS NULL OR run_after <= ?)
                       AND target NOT IN (SELECT target FROM jobs WHERE status = 'running')  -- parallel loops: one domain is checked by one loop at a time
                       ORDER BY priority DESC, id LIMIT 1)
           RETURNING *""",
        (now, now),
    ).fetchone()
    conn.commit()
    return dict(row) if row else None


async def recover_running_jobs() -> None:
    await db.run(_recover)


async def claim_next() -> dict | None:
    return await db.run(_claim)


def _finish_in(conn, job_id: int, status: str, error: str | None = None) -> None:
    conn.execute("UPDATE jobs SET status = ?, finished_at = ?, error = ? WHERE id = ?", (status, _now(), error, job_id))


def _fail_or_retry(conn, job: dict, error: str, delays: list[float]) -> None:
    if job["attempts"] >= job["max_attempts"]:
        _finish_in(conn, job["id"], "failed", error)
    else:
        delay = delays[min(job["attempts"], len(delays)) - 1]
        run_after = (datetime.now(UTC) + timedelta(seconds=delay)).isoformat().replace("+00:00", "Z")
        conn.execute(
            "UPDATE jobs SET status = 'queued', started_at = NULL, run_after = ?, error = ? WHERE id = ?",
            (run_after, error, job["id"]),
        )
    conn.commit()


async def finish(job_id: int, status: str, error: str | None = None) -> None:
    def update(conn):
        _finish_in(conn, job_id, status, error)
        conn.commit()

    await db.run(update)


async def process_next(settings, http) -> bool:
    """Claim one job and leave an explicit terminal state for unsupported work."""
    job = await claim_next()
    if job is None:
        return False
    if job["kind"] not in ("check_domain", "recheck"):
        await finish(job["id"], "failed", f"unknown job kind: {job['kind']}")
        return True
    try:
        await (_check_domain if job["kind"] == "check_domain" else _recheck)(job, settings, http)
    except Exception as exc:  # noqa: BLE001 - one bad job must not stop the queue
        delays = settings.sources["worker"].extra["retry_delays_s"]
        await _record_failure(job, f"{type(exc).__name__}: {exc}", delays, settings.sources["worker"].extra)
    return True


async def _record_failure(job: dict, error: str, delays: list[float], cfg: dict) -> None:
    """Write the retry/failed state even when the database is busy; a job left 'running' would block its domain until restart."""
    tries = cfg.get("record_failure_tries", 5)
    for attempt in range(tries):
        try:
            await db.run(_fail_or_retry, job, error, delays)
            return
        except sqlite3.OperationalError:
            if attempt == tries - 1:
                raise  # the loop restarts and recover_running_jobs re-queues the row
            await asyncio.sleep(cfg.get("record_failure_pause_s", 2))


def _reassess(conn, domain_id: int, fqdn: str, settings, timestamp: str):
    """Score the domain's current facts (intake lookalike + last check), save the assessment row and the domain state."""
    facts = [
        FactRow(
            r["type"],
            json.loads(r["value_json"]),
            r["source"],
            r["observed_at"],
            r["fetched_at"],
            r["status"],
            r["error"],
            r["data_mode"],
            r["raw_ref"],
            r["id"],
            r["domain_id"],
        )
        for r in db.current_facts(conn, domain_id)
    ]
    row = conn.execute(
        "SELECT verdict, reason, analyst, created_at FROM feedback WHERE domain_id = ? ORDER BY id DESC LIMIT 1",
        (domain_id,),
    ).fetchone()
    # stored url paths come only from feeds that list full URLs
    paths = [urlsplit(r["url"]).path for r in conn.execute("SELECT url FROM urls WHERE domain_id = ?", (domain_id,))]
    edges, confirmed, listed, parked_peers = graph.inputs_for_assessment(
        conn, fqdn, settings.scoring, settings.shared_infra
    )
    assessment = assess(
        fqdn,
        facts,
        edges,
        Verdict(*row) if row else None,
        confirmed,
        settings.brands,
        settings.scoring,
        paths,
        listed,
        parked_peers,
    )
    conn.execute(
        "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            domain_id,
            assessment.rule_version,
            assessment.risk_score,
            assessment.coverage,
            assessment.state,
            json.dumps(assessment.flags),
            json.dumps(assessment.components),
            json.dumps(assessment.evidence_ids),
            timestamp,
        ),
    )
    conn.execute(
        "UPDATE domains SET state = ?, risk_score = ?, coverage = ?, last_assessed_at = ? WHERE id = ?",
        (assessment.state, assessment.risk_score, assessment.coverage, timestamp, domain_id),
    )
    if any(f.type == "in_feed" and f.status == "ok" and f.value.get("listed") for f in facts):
        _queue_neighbour_rechecks(conn, fqdn, settings)
    return assessment


def _queue_neighbour_rechecks(conn, fqdn: str, settings) -> None:
    """Event: fqdn is confirmed or feed-listed, so each linked NOISE / GRAY_LOW domain gets an immediate recheck (one per pair)."""
    low = _low_domains(conn)
    for edge in graph.inputs_for_assessment(conn, fqdn, settings.scoring, settings.shared_infra)[0]:
        other = edge.b if edge.a == fqdn else edge.a
        if other in low:
            enqueue_in(conn, "recheck", other, {}, f"recheck:{other}:edge:{fqdn}")


def recheck_neighbours(conn, fqdn: str, settings) -> None:
    """Event: an analyst confirmed fqdn as scam."""
    _queue_neighbour_rechecks(conn, fqdn, settings)
    conn.commit()


def _low_domains(conn, fqdn: str | None = None) -> dict[str, str]:
    """fqdn -> registrable of domains whose latest assessment is NOISE or GRAY_LOW (the ones re-assessed on events)."""
    rows = conn.execute(
        """SELECT d.fqdn, d.registrable, a.state, a.flags_json FROM domains d JOIN assessments a ON a.id = (SELECT MAX(id) FROM assessments WHERE domain_id = d.id)
                           WHERE ? IS NULL OR d.fqdn = ?""",
        (fqdn, fqdn),
    )
    return {row[0]: row[1] for row in rows if row[2] == "NOISE" or "GRAY_LOW" in json.loads(row[3] or "[]")}


def recheck_listed(conn, listed: set[str], stamp: str) -> None:
    """Event: a feed diff lists the fqdn or its registrable. Queue an immediate recheck (DNS + feed_match) instead of waiting for the 24 h timer."""
    for fqdn, registrable in _low_domains(conn).items():
        if fqdn in listed or registrable in listed:
            enqueue_in(conn, "recheck", fqdn, {}, f"recheck:{fqdn}:feed:{stamp}")
    conn.commit()


async def recheck_resolving(settings, http) -> None:
    """Event: a NOISE / GRAY_LOW domain without a resolving A/AAAA now resolves. One DNS look per such domain; queues an immediate recheck."""
    ctx = runtime.make_ctx(settings, http, "auto")

    def candidates(conn):
        out = []
        for fqdn in _low_domains(conn):
            ok = conn.execute(
                """SELECT 1 FROM facts f JOIN domains d ON d.id = f.domain_id WHERE d.fqdn = ? AND f.type IN ('dns_a', 'dns_aaaa') AND f.status = 'ok'
                                 AND (f.job_id IS NULL OR f.job_id = (SELECT MAX(id) FROM jobs WHERE kind = 'check_domain' AND target = d.fqdn AND status IN ('done', 'partial')))""",
                (fqdn,),
            ).fetchone()
            if not ok:
                out.append(fqdn)
        return out

    stamp = _now()
    for fqdn in await db.run(candidates):
        if any(f.status == "ok" and f.type in ("dns_a", "dns_aaaa") for f in await dns.run(fqdn, ctx)):
            await enqueue("recheck", fqdn, {}, f"recheck:{fqdn}:dns:{stamp[:13]}")


def has_new_certificate(conn, fqdn: str, seen_at: str) -> bool:
    """Event: a CT entry newer than the last assessment of a NOISE / GRAY_LOW domain."""
    row = conn.execute("SELECT last_assessed_at FROM domains WHERE fqdn = ?", (fqdn,)).fetchone()
    return bool(row and row[0] and seen_at > row[0] and fqdn in _low_domains(conn, fqdn))


async def _recheck(job: dict, settings, http) -> None:
    """+24 h look at a NOISE / GRAY_LOW domain: DNS and feed match only (no budgeted source), replace those facts in the last check, re-apply the brand rules, re-assess."""
    ctx = runtime.make_ctx(settings, http, "auto")
    fresh = [*await dns.run(job["target"], ctx), *await feed_match.run(job["target"], ctx)]

    def store(conn):
        try:
            row = conn.execute("SELECT id FROM domains WHERE fqdn = ?", (job["target"],)).fetchone()
            if row is None:
                raise LookupError(f"domain {job['target']} was not submitted via intake")
            last = conn.execute(
                "SELECT id FROM jobs WHERE kind = 'check_domain' AND target = ? AND status IN ('done', 'partial') ORDER BY id DESC LIMIT 1",
                (job["target"],),
            ).fetchone()
            marks = ",".join("?" * len(fresh))
            conn.execute(
                f"DELETE FROM facts WHERE domain_id = ? AND job_id IS ? AND type IN ({marks})",
                (row[0], last[0] if last else None, *[f.type for f in fresh]),
            )
            conn.executemany(
                "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, error, data_mode, raw_ref, job_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        row[0],
                        f.type,
                        json.dumps(f.value),
                        f.source,
                        f.observed_at,
                        f.fetched_at,
                        f.status,
                        f.error,
                        f.data_mode,
                        f.raw_ref,
                        last[0] if last else None,
                    )
                    for f in fresh
                ],
            )
            if last:  # rules may have changed since the check: re-apply them (a repeated recheck replaces its own earlier answer)
                conn.execute(
                    "DELETE FROM facts WHERE domain_id = ? AND job_id = ? AND type = 'lookalike' AND source = 'brand_check'",
                    (row[0], last[0]),
                )
                _recheck_brand(conn, row[0], job["target"], settings, _now(), last[0])
            _reassess(conn, row[0], job["target"], settings, _now())
            _finish_in(conn, job["id"], "done")
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    await db.run(store)
    triage_ai.auto_in_background(job["target"])  # the new assessment is judged once if still gray


def _ensure_brand_check(conn, domain_id: int, fqdn: str, settings, timestamp: str) -> None:
    """Every checked domain gets its brand check, whatever way it came in (paste, search, CT, feed). No hit stores nothing: unknown is not risk."""
    known = conn.execute(
        "SELECT value_json FROM facts WHERE domain_id = ? AND type = 'lookalike' AND status = 'ok' ORDER BY id DESC LIMIT 1",
        (domain_id,),
    ).fetchone()
    brand = json.loads(known[0]).get("brand") if known else None
    if (
        not known
        and not conn.execute("SELECT 1 FROM facts WHERE domain_id = ? AND type = 'lookalike'", (domain_id,)).fetchone()
    ):
        found_by, data_mode = conn.execute(
            "SELECT found_by, data_mode FROM domains WHERE id = ?", (domain_id,)
        ).fetchone()
        url_path = next(
            (
                p
                for p in (
                    urlsplit(r[0]).path for r in conn.execute("SELECT url FROM urls WHERE domain_id = ?", (domain_id,))
                )
                if p not in ("", "/")
            ),
            None,
        )
        hit = lookalike.match(
            fqdn, settings.brands, "ct" if found_by in ("ct_tiled", "nrd") else "feed", url_path
        ) or lookalike.smishing_pattern(fqdn)
        if hit:
            brand = hit["brand"]
            conn.execute(
                "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, data_mode) VALUES (?, 'lookalike', ?, 'brand_check', ?, ?, 'ok', ?)",
                (domain_id, json.dumps(lookalike.fact_value(hit)), timestamp, timestamp, data_mode),
            )
    if brand:
        conn.execute("UPDATE domains SET brand_id = COALESCE(brand_id, ?) WHERE id = ?", (brand, domain_id))


def _recheck_brand(conn, domain_id: int, fqdn: str, settings, timestamp: str, job_id: int) -> None:
    """Brand rules change after intake: if the name-derived intake hit differs from what the current rules say, store the current answer as this check's
    own `lookalike` fact (it supersedes the intake one in current_facts; a missing fact carries the reason). Search/page evidence is not touched."""
    marks = ",".join("?" * len(db.NAME_BRAND_SOURCES))
    old = [
        json.loads(r[0])
        for r in conn.execute(
            f"SELECT value_json FROM facts WHERE domain_id = ? AND type = 'lookalike' AND status = 'ok' AND job_id IS NULL AND source IN ({marks})",
            (domain_id, *db.NAME_BRAND_SOURCES),
        )
    ]
    if not old:
        return
    data_mode = conn.execute("SELECT data_mode FROM domains WHERE id = ?", (domain_id,)).fetchone()[0]
    url_path = next(
        (
            p
            for p in (
                urlsplit(r[0]).path for r in conn.execute("SELECT url FROM urls WHERE domain_id = ?", (domain_id,))
            )
            if p not in ("", "/")
        ),
        None,
    )
    hit = (
        lookalike.match(fqdn, settings.brands, old[-1].get("mode", "feed"), url_path)
        or (url_path and lookalike.path_match(fqdn, settings.brands, url_path))
        or lookalike.smishing_pattern(fqdn)
    )
    if (
        not hit and old[-1].get("method") == "generic_name"
    ):  # a brandless name is re-judged by its own rule, not by the brand rules (all 546 turned NOISE)
        hit = lookalike.generic_name(fqdn, settings.scoring, settings.shared_infra.get("host_suffixes", []))
        if hit and {k: v for k, v in old[-1].items() if k != "log"} == lookalike.fact_value(hit):
            return
    value = lookalike.fact_value(hit) if hit else None
    if value in old:
        return
    error = None if hit else f"brand rule no longer matches (rule_version {settings.scoring['rule_version']})"
    conn.execute(
        "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, error, data_mode, job_id) VALUES (?, 'lookalike', ?, 'brand_check', ?, ?, ?, ?, ?, ?)",
        (domain_id, json.dumps(value), timestamp, timestamp, "ok" if hit else "missing", error, data_mode, job_id),
    )


async def _check_domain(job: dict, settings, http) -> None:
    pool = "manual" if json.loads(job["payload_json"]).get("found_by") == "manual" else "auto"
    ctx = runtime.make_ctx(settings, http, pool)
    dns_facts, asn_facts, rdap_facts, cert_facts, feed_facts = await asyncio.gather(
        dns.run(job["target"], ctx),
        asn.run(job["target"], ctx),
        rdap.run(job["target"], ctx),
        certspotter.run(job["target"], ctx),
        feed_match.run(job["target"], ctx),
    )

    def store(conn):
        try:
            timestamp = _now()
            row = conn.execute("SELECT id FROM domains WHERE fqdn = ?", (job["target"],)).fetchone()
            if row is None:
                raise LookupError(f"domain {job['target']} was not submitted via intake")
            domain_id = row[0]
            _ensure_brand_check(conn, domain_id, job["target"], settings, timestamp)
            conn.execute("DELETE FROM facts WHERE job_id = ?", (job["id"],))
            conn.executemany(
                "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, error, data_mode, raw_ref, job_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        domain_id,
                        fact.type,
                        json.dumps(fact.value),
                        fact.source,
                        fact.observed_at,
                        fact.fetched_at,
                        fact.status,
                        fact.error,
                        fact.data_mode,
                        fact.raw_ref,
                        job["id"],
                    )
                    for fact in [*dns_facts, *asn_facts, *rdap_facts, *cert_facts, *feed_facts]
                ],
            )
            _recheck_brand(conn, domain_id, job["target"], settings, timestamp, job["id"])
            _finish_in(conn, job["id"], "done")  # first: the facts of this job become the current ones
            assessment = _reassess(conn, domain_id, job["target"], settings, timestamp)
            if assessment.state == "NOISE" or "GRAY_LOW" in assessment.flags:
                run_after = (
                    (datetime.now(UTC) + timedelta(hours=settings.sources["worker"].extra["recheck_hours"]))
                    .isoformat()
                    .replace("+00:00", "Z")
                )
                enqueue_in(
                    conn, "recheck", job["target"], {}, f"recheck:{job['target']}", run_after=run_after
                )  # one per domain
            conn.commit()
        except BaseException:
            conn.rollback()  # partial facts must not be committed by the retry path
            raise

    await db.run(store)
    explain.auto_in_background(
        job["target"]
    )  # sweep over the queue cases (REVIEW_HIGH first), quota-limited, does not hold the worker
    triage_ai.auto_in_background(job["target"])  # gray cases only, once per assessment, within the judge's daily caps


def enqueue_in(
    conn, kind: str, target: str, payload: dict, idem_key: str, priority: int = 0, run_after: str | None = None
) -> None:
    """Insert a job inside the caller's transaction (no commit)."""
    conn.execute(
        "INSERT OR IGNORE INTO jobs (kind, target, payload_json, priority, idem_key, run_after, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (kind, target, json.dumps(payload), priority, idem_key, run_after, _now()),
    )


async def enqueue(kind: str, target: str, payload: dict, idem_key: str, priority: int = 0) -> None:
    def insert(conn):
        enqueue_in(conn, kind, target, payload, idem_key, priority)
        conn.commit()

    await db.run(insert)
