import asyncio
import sqlite3

from scamshield import db
from scamshield.contracts import Fact


def test_worker_requeues_interrupted_job_and_claims_it(tmp_path):
    from scamshield import worker

    path = tmp_path / "scamshield.db"
    db.init(str(path))
    conn = sqlite3.connect(path)
    conn.execute("""INSERT INTO jobs (kind, target, payload_json, status, idem_key)
                 VALUES ('check_domain', 'example.com', '{}', 'running', 'check_domain:example.com:1')""")
    conn.commit()

    asyncio.run(worker.recover_running_jobs())
    job = asyncio.run(worker.claim_next())

    assert job["status"] == "running"
    assert job["target"] == "example.com"


def test_worker_marks_claimed_job_done(tmp_path):
    from scamshield import worker

    db.init(str(tmp_path / "scamshield.db"))
    asyncio.run(worker.enqueue("check_domain", "example.com", {}, "check_domain:example.com:1"))

    asyncio.run(worker.finish(1, "done"))

    status = sqlite3.connect(tmp_path / "scamshield.db").execute("SELECT status FROM jobs WHERE id = 1").fetchone()[0]
    assert status == "done"


def test_process_next_marks_unknown_job_failed(tmp_path):
    from scamshield import worker

    db.init(str(tmp_path / "scamshield.db"))
    asyncio.run(worker.enqueue("unknown", "x", {}, "unknown:x:1"))

    assert asyncio.run(worker.process_next(None, None)) is True

    status, error = (
        sqlite3.connect(tmp_path / "scamshield.db").execute("SELECT status, error FROM jobs WHERE id = 1").fetchone()
    )
    assert status == "failed"
    assert "unknown" in error


def test_process_next_check_domain_stores_facts(tmp_path, monkeypatch):
    from scamshield import config, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def dns_run(fqdn, ctx):
        return [Fact("dns_a", {"records": ["93.184.216.34"]}, "dns", None, "2026-11-19T08:00:00Z", "ok")]

    async def asn_run(fqdn, ctx):
        return [Fact("ip_asn", {"ip": "93.184.216.34", "asn": 15133}, "asn", None, "2026-11-19T08:00:00Z", "ok")]

    async def rdap_run(fqdn, ctx):
        return [Fact("created_at", {}, "rdap", None, "2026-11-19T08:00:00Z", "missing")]

    monkeypatch.setattr(worker.dns, "run", dns_run)
    monkeypatch.setattr(worker.asn, "run", asn_run)
    monkeypatch.setattr(worker.rdap, "run", rdap_run)
    monkeypatch.setattr(worker.certspotter, "run", lambda fqdn, ctx: _empty())
    monkeypatch.setattr(worker.feed_match, "run", lambda fqdn, ctx: _empty())
    asyncio.run(intake.submit("example.com", "manual", [], 10))

    assert asyncio.run(worker.process_next(config.load(), None)) is True

    conn = sqlite3.connect(tmp_path / "scamshield.db")
    assert conn.execute("SELECT status FROM jobs").fetchone()[0] == "done"
    assert conn.execute("SELECT count(*) FROM facts").fetchone()[0] == 3


def test_enricher_exception_fails_job_and_next_job_is_processed(tmp_path, monkeypatch):
    from scamshield import config, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def dns_run(fqdn, ctx):
        if fqdn == "bad.example":
            raise RuntimeError("boom")
        return [Fact("dns_a", {"records": ["93.184.216.34"]}, "dns", None, "2026-11-19T08:00:00Z", "ok")]

    async def other_run(fqdn, ctx):
        return []

    monkeypatch.setattr(worker.dns, "run", dns_run)
    monkeypatch.setattr(worker.asn, "run", other_run)
    monkeypatch.setattr(worker.rdap, "run", other_run)
    monkeypatch.setattr(worker.certspotter, "run", other_run)
    monkeypatch.setattr(worker.feed_match, "run", lambda fqdn, ctx: _empty())
    asyncio.run(intake.submit("bad.example", "manual", [], 1))
    asyncio.run(intake.submit("good.example", "manual", [], 0))
    settings = config.load()

    assert asyncio.run(worker.process_next(settings, None)) is True
    assert asyncio.run(worker.process_next(settings, None)) is True

    rows = (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT target, status, error FROM jobs ORDER BY id")
        .fetchall()
    )
    assert rows[0][1] == "queued" and "boom" in rows[0][2]
    assert rows[1][1] == "done"


def _stub_enrichers(monkeypatch, worker, dns_run):
    async def other_run(fqdn, ctx):
        return [Fact("ip_asn", {"asn": 1}, "asn", None, "2026-11-19T08:00:00Z", "ok")]

    monkeypatch.setattr(worker.dns, "run", dns_run)
    monkeypatch.setattr(worker.asn, "run", other_run)
    monkeypatch.setattr(worker.rdap, "run", lambda fqdn, ctx: _empty())
    monkeypatch.setattr(worker.certspotter, "run", lambda fqdn, ctx: _empty())
    monkeypatch.setattr(worker.feed_match, "run", lambda fqdn, ctx: _empty())


async def _empty():
    return []


def test_rerun_after_kill_does_not_duplicate_facts(tmp_path, monkeypatch):
    from scamshield import config, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def dns_run(fqdn, ctx):
        return [Fact("dns_a", {"records": ["1.2.3.4"]}, "dns", None, "2026-11-19T08:00:00Z", "ok")]

    _stub_enrichers(monkeypatch, worker, dns_run)
    asyncio.run(intake.submit("example.com", "manual", [], 0))
    settings = config.load()
    job = asyncio.run(worker.claim_next())
    asyncio.run(worker._check_domain(job, settings, None))
    sqlite3.connect(tmp_path / "scamshield.db").execute(
        "UPDATE jobs SET status = 'running'"
    ).connection.commit()  # as if killed before finish
    asyncio.run(worker.recover_running_jobs())

    assert asyncio.run(worker.process_next(settings, None)) is True

    conn = sqlite3.connect(tmp_path / "scamshield.db")
    assert conn.execute("SELECT count(*) FROM facts WHERE type IN ('dns_a','ip_asn')").fetchone()[0] == 2
    assert conn.execute("SELECT status FROM jobs").fetchone()[0] == "done"


def test_failure_requeues_with_pause_then_fails_after_max_attempts(tmp_path, monkeypatch):
    from scamshield import config, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def dns_run(fqdn, ctx):
        raise RuntimeError("boom")

    _stub_enrichers(monkeypatch, worker, dns_run)
    asyncio.run(intake.submit("bad.example", "manual", [], 0))
    settings = config.load()
    conn = sqlite3.connect(tmp_path / "scamshield.db")

    assert asyncio.run(worker.process_next(settings, None)) is True
    status, attempts, run_after, error = conn.execute("SELECT status, attempts, run_after, error FROM jobs").fetchone()
    assert (status, attempts) == ("queued", 1) and run_after > "2026" and "boom" in error
    assert asyncio.run(worker.process_next(settings, None)) is False  # pause not over

    for expected in ("queued", "failed"):
        conn.execute("UPDATE jobs SET run_after = '2000-01-01T00:00:00Z'")
        conn.commit()
        assert asyncio.run(worker.process_next(settings, None)) is True
        assert conn.execute("SELECT status FROM jobs").fetchone()[0] == expected
    assert conn.execute("SELECT attempts, error FROM jobs").fetchone()[0] == 3


def test_locked_db_while_recording_failure_never_leaves_job_running(tmp_path, monkeypatch):
    """A busy database while the failure is written must not strand the job as 'running' (fresh install under load)."""
    from scamshield import config, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def dns_run(fqdn, ctx):
        raise sqlite3.OperationalError("database is locked")

    _stub_enrichers(monkeypatch, worker, dns_run)
    real, calls = worker._fail_or_retry, []

    def flaky(conn, job, error, delays):
        calls.append(1)
        if len(calls) < 3:
            raise sqlite3.OperationalError("database is locked")
        real(conn, job, error, delays)

    monkeypatch.setattr(worker, "_fail_or_retry", flaky)
    asyncio.run(intake.submit("busy.example", "manual", [], 0))

    settings = config.load()
    settings.sources["worker"].extra["record_failure_pause_s"] = 0
    assert asyncio.run(worker.process_next(settings, None)) is True
    status, error = sqlite3.connect(tmp_path / "scamshield.db").execute("SELECT status, error FROM jobs").fetchone()
    assert status == "queued" and "locked" in error and len(calls) == 3


def test_recover_counts_interrupted_attempt_and_fails_at_limit(tmp_path):
    from scamshield import worker

    path = tmp_path / "scamshield.db"
    db.init(str(path))
    conn = sqlite3.connect(path)
    conn.execute("""INSERT INTO jobs (kind, target, status, attempts, max_attempts, idem_key)
                 VALUES ('check_domain', 'a.com', 'running', 3, 3, 'k1')""")
    conn.commit()

    asyncio.run(worker.recover_running_jobs())

    assert conn.execute("SELECT status, error FROM jobs").fetchone() == ("failed", "interrupted")


def test_old_database_without_job_id_opens(tmp_path):
    path = tmp_path / "scamshield.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """CREATE TABLE domains (id INTEGER PRIMARY KEY AUTOINCREMENT, fqdn TEXT);
           CREATE TABLE facts (id INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL, type TEXT NOT NULL,
             value_json TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT, fetched_at TEXT NOT NULL,
             status TEXT NOT NULL, error TEXT, data_mode TEXT NOT NULL DEFAULT 'LIVE', raw_ref TEXT);"""
    )
    conn.commit()

    db.init(str(path))
    db.init(str(path))

    assert "job_id" in [row[1] for row in conn.execute("PRAGMA table_info(facts)")]


def test_failure_inside_store_leaves_no_facts(tmp_path, monkeypatch):
    from scamshield import config, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def dns_run(fqdn, ctx):
        return [Fact("dns_a", {"ips": ["1.1.1.1"]}, "dns", None, "2026-11-19T08:00:00Z", "ok")]

    def bad_assess(*args, **kwargs):
        raise ValueError("assess broke")

    _stub_enrichers(monkeypatch, worker, dns_run)
    monkeypatch.setattr(worker, "assess", bad_assess)
    asyncio.run(intake.submit("half.example", "manual", [], 0))
    settings = config.load()
    conn = sqlite3.connect(tmp_path / "scamshield.db")

    for _ in range(3):
        conn.execute("UPDATE jobs SET run_after = '2000-01-01T00:00:00Z'")
        conn.commit()
        asyncio.run(worker.process_next(settings, None))
    assert conn.execute("SELECT status FROM jobs").fetchone()[0] == "failed"
    assert conn.execute("SELECT count(*) FROM facts WHERE job_id IS NOT NULL").fetchone()[0] == 0


def _lookalike_candidate(fqdn, keyword="aramex", label="aramax"):
    from scamshield.contracts import Candidate

    return Candidate(
        fqdn,
        "ct_tiled",
        "2026-11-19T08:00:00Z",
        "LIVE",
        {
            "brand": keyword,
            "keyword": keyword,
            "label": label,
            "score": 0.8,
            "method": "edit-distance",
            "position": "registrable",
            "restricted_zone": False,
            "context": "none",
            "context_words": [],
            "mode": "ct",
        },
    )


def _facts_json(conn, fqdn):
    return conn.execute(
        "SELECT a.components_json, a.flags_json, a.state FROM assessments a JOIN domains d ON d.id = a.domain_id WHERE d.fqdn = ? ORDER BY a.id DESC",
        (fqdn,),
    ).fetchall()


def test_gray_low_gets_one_recheck_at_24h_with_dns_and_feed_only_and_reassessment(tmp_path, monkeypatch):
    import json

    from scamshield import config, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))
    state = {"listed": False}

    async def dns_run(fqdn, ctx):
        stamp = "2026-11-19T08:00:00Z"
        return (
            [Fact("dns_a", {"records": ["1.2.3.4"]}, "dns", None, stamp, "ok")]
            if state["listed"]
            else [Fact("dns_a", {}, "dns", None, stamp, "missing", "nxdomain")]
        )

    async def feed_run(fqdn, ctx):
        value = {"listed": True, "feeds": ["phishing_database"]} if state["listed"] else {"listed": False}
        return [Fact("in_feed", value, "feed_match", None, "2026-11-19T08:00:00Z", "ok")]

    _stub_enrichers(monkeypatch, worker, dns_run)
    monkeypatch.setattr(worker.feed_match, "run", feed_run)
    asyncio.run(intake.store_candidates([_lookalike_candidate("aramax-track.com")], "ct", None, 86400))
    settings = config.load()
    asyncio.run(worker.process_next(settings, None))
    asyncio.run(worker.process_next(settings, None))  # nothing else is due yet

    conn = sqlite3.connect(tmp_path / "scamshield.db")
    first = _facts_json(conn, "aramax-track.com")
    recheck = conn.execute("SELECT status, run_after FROM jobs WHERE kind = 'recheck'").fetchall()
    assert json.loads(first[0][0])["band"] == "GRAY_LOW" and "GRAY_LOW" in json.loads(first[0][1])
    assert len(recheck) == 1 and recheck[0][0] == "queued" and recheck[0][1] > "2026-11-20"  # +24 h, in the future

    async def forbidden(fqdn, ctx):
        raise AssertionError("recheck must use DNS and feed_match only")

    for name in ("asn", "rdap", "certspotter"):
        monkeypatch.setattr(getattr(worker, name), "run", forbidden)
    state["listed"] = True
    conn.execute("UPDATE jobs SET run_after = '2000-01-01T00:00:00Z' WHERE kind = 'recheck'")
    conn.commit()
    assert asyncio.run(worker.process_next(settings, None)) is True

    after = _facts_json(sqlite3.connect(tmp_path / "scamshield.db"), "aramax-track.com")
    assert json.loads(after[0][0])["band"] == "GRAY" and after[0][2] == "REVIEW" and len(after) == 2
    assert (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT status FROM jobs WHERE kind = 'recheck'")
        .fetchone()[0]
        == "done"
    )
    asyncio.run(worker.process_next(settings, None))  # a second check_domain must not queue a second recheck
    assert (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT count(*) FROM jobs WHERE kind = 'recheck'")
        .fetchone()[0]
        == 1
    )


def test_restored_domain_with_unclear_verdict_is_not_noise_again(tmp_path, monkeypatch):
    from scamshield import config, feedback, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def dns_run(fqdn, ctx):
        return [Fact("dns_a", {}, "dns", None, "2026-11-19T08:00:00Z", "missing", "nxdomain")]

    _stub_enrichers(monkeypatch, worker, dns_run)
    candidate = _lookalike_candidate("du.ac.bd", "du", "du")
    candidate.metadata.update(restricted_zone=True, method="token")
    asyncio.run(intake.store_candidates([candidate], "ct", None, 86400))
    settings = config.load()
    asyncio.run(worker.process_next(settings, None))
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    assert _facts_json(conn, "du.ac.bd")[0][2] == "NOISE"

    asyncio.run(feedback.save(1, "unclear", "restored: returned to queue", None))
    candidate.observed_at = "2026-11-19T09:30:00Z"
    asyncio.run(intake.store_candidates([candidate], "ct", None, 3600))  # a new sighting re-assesses
    asyncio.run(worker.process_next(settings, None))

    assert _facts_json(sqlite3.connect(tmp_path / "scamshield.db"), "du.ac.bd")[0][2] != "NOISE"


def test_parallel_loops_never_claim_two_jobs_of_one_domain(tmp_path):
    from scamshield import worker

    path = tmp_path / "scamshield.db"
    db.init(str(path))
    conn = sqlite3.connect(path)
    for i, target in enumerate(["a.com", "a.com", "b.com"]):
        conn.execute(
            "INSERT INTO jobs (kind, target, payload_json, status, idem_key) VALUES ('check_domain', ?, '{}', 'queued', ?)",
            (target, f"k{i}"),
        )
    conn.commit()

    first, second, third = (asyncio.run(worker.claim_next()) for _ in range(3))

    assert [first["target"], second["target"]] == ["a.com", "b.com"]  # the second a.com job waits while the first runs
    assert third is None
