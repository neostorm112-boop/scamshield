"""A NOISE / GRAY_LOW domain is re-assessed when new evidence arrives, not only by the +24 h timer."""

import asyncio
import json
import sqlite3

from scamshield import config, db, intake, worker
from scamshield.connectors import feeds
from scamshield.contracts import Candidate, Fact

STAMP = "2026-11-19T08:00:00Z"
FQDN = "aramax-track.com"


def _candidate(fqdn=FQDN, source="ct_tiled", observed_at=STAMP):
    return Candidate(
        fqdn,
        source,
        observed_at,
        "LIVE",
        {
            "brand": "aramex",
            "keyword": "aramex",
            "label": "aramax",
            "score": 0.8,
            "method": "edit-distance",
            "position": "registrable",
            "restricted_zone": False,
            "context": "none",
            "context_words": [],
            "mode": "ct",
        },
    )


def _setup(tmp_path, monkeypatch, dns_ok=False):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))
    state = {"dns_ok": dns_ok}

    async def dns_run(fqdn, ctx):
        return (
            [Fact("dns_a", {"records": ["1.2.3.4"]}, "dns", None, STAMP, "ok")]
            if state["dns_ok"]
            else [Fact("dns_a", {}, "dns", None, STAMP, "missing", "nxdomain")]
        )

    async def asn_run(fqdn, ctx):
        return [Fact("ip_asn", {"asn": 1}, "asn", None, STAMP, "ok")]

    async def feed_run(fqdn, ctx):
        return [Fact("in_feed", {"listed": False}, "feed_match", None, STAMP, "ok")]

    async def nothing(fqdn, ctx):
        return []

    for name, run in (
        ("dns", dns_run),
        ("asn", asn_run),
        ("rdap", nothing),
        ("certspotter", nothing),
        ("feed_match", feed_run),
    ):
        monkeypatch.setattr(getattr(worker, name), "run", run)
    asyncio.run(intake.store_candidates([_candidate()], "ct", None, 86400))
    settings = config.load()
    asyncio.run(worker.process_next(settings, None))  # first check: GRAY_LOW, timer recheck queued for +24 h
    return settings, state


def _bands(tmp_path):
    rows = (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT components_json FROM assessments ORDER BY id")
        .fetchall()
    )
    return [json.loads(r[0])["band"] for r in rows]


def _due_jobs(tmp_path, kind):
    return (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT id FROM jobs WHERE kind = ? AND status = 'queued' AND run_after IS NULL", (kind,))
        .fetchall()
    )


def test_new_feed_listing_queues_immediate_recheck_and_reassesses(tmp_path, monkeypatch):
    settings, _ = _setup(tmp_path, monkeypatch)
    assert _bands(tmp_path) == ["GRAY_LOW"]

    asyncio.run(db.run(worker.recheck_listed, {"aramax-track.com"}, "2026-11-20T01:00:00Z"))
    asyncio.run(db.run(worker.recheck_listed, {"aramax-track.com"}, "2026-11-20T01:00:00Z"))  # same diff twice: one job

    assert len(_due_jobs(tmp_path, "recheck")) == 1
    assert asyncio.run(worker.process_next(settings, None)) is True  # runs now, the timer job is still +24 h away
    assert len(_bands(tmp_path)) == 2


def test_feed_event_matches_the_registrable_of_a_subdomain(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.execute("UPDATE domains SET fqdn = 'www.aramax-track.com' WHERE fqdn = 'aramax-track.com'")
    conn.commit()

    asyncio.run(
        db.run(worker.recheck_listed, {"aramax-track.com"}, "2026-11-20T01:00:00Z")
    )  # the feed lists the registrable

    assert len(_due_jobs(tmp_path, "recheck")) == 1


def test_feed_event_ignores_domains_that_are_not_noise_or_gray_low(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.execute("UPDATE assessments SET state = 'REVIEW_HIGH', flags_json = '[]'")
    conn.commit()

    asyncio.run(db.run(worker.recheck_listed, {"aramax-track.com"}, "2026-11-20T01:00:00Z"))

    assert _due_jobs(tmp_path, "recheck") == []


def test_run_once_hooks_the_feed_diff_to_the_event(tmp_path, monkeypatch):
    from scamshield import runtime

    settings, _ = _setup(tmp_path, monkeypatch)
    seen = []

    async def text(*args, **kwargs):
        return "x.example\n"

    monkeypatch.setattr(feeds, "_swap", lambda *args: ([FQDN], ["old.example"]))
    monkeypatch.setattr(worker, "recheck_listed", lambda conn, listed, stamp: seen.append(listed))
    monkeypatch.setattr(feeds.sources, "fetch_text_limited", text)

    asyncio.run(feeds.run_once(runtime.make_ctx(settings, None, "auto")))

    assert seen == [{FQDN, "old.example"}]


def test_new_ct_certificate_after_last_assessment_triggers_a_fresh_check(tmp_path, monkeypatch):
    settings, _ = _setup(tmp_path, monkeypatch)
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.execute("UPDATE domains SET last_assessed_at = '2026-11-19T09:00:00Z'")
    conn.commit()

    asyncio.run(
        intake.store_candidates([_candidate(observed_at="2026-11-19T08:30:00Z")], "ct", None, 86400)
    )  # same re-check window, before the assessment
    assert _due_jobs(tmp_path, "check_domain") == []
    asyncio.run(
        intake.store_candidates([_candidate(observed_at="2026-11-19T10:00:00Z")], "ct", None, 86400)
    )  # a certificate newer than the assessment

    assert len(_due_jobs(tmp_path, "check_domain")) == 1
    assert asyncio.run(worker.process_next(settings, None)) is True
    assert len(_bands(tmp_path)) == 2


def test_dns_watch_queues_recheck_only_when_a_low_domain_starts_resolving(tmp_path, monkeypatch):
    settings, state = _setup(tmp_path, monkeypatch)

    asyncio.run(worker.recheck_resolving(settings, None))  # still NXDOMAIN
    assert _due_jobs(tmp_path, "recheck") == []

    state["dns_ok"] = True
    asyncio.run(worker.recheck_resolving(settings, None))
    asyncio.run(worker.recheck_resolving(settings, None))  # a second sweep before the job runs adds nothing
    assert len(_due_jobs(tmp_path, "recheck")) == 1

    assert asyncio.run(worker.process_next(settings, None)) is True
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    rows = conn.execute("SELECT components_json FROM assessments ORDER BY id").fetchall()
    assert len(rows) == 2 and any("resolves" in line for line in json.loads(rows[1][0])["breakdown"])


def test_low_domains_ignores_flag_text_outside_the_flags_list(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.row_factory = sqlite3.Row
    conn.execute("UPDATE assessments SET state = 'GRAY', flags_json = '[\"NEG:GRAY_LOW_x\"]'")
    assert worker._low_domains(conn) == {}


def _listed_neighbour(tmp_path, listed=True):
    """A second domain on the same IP, with its own facts, as if its check had finished."""
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    domain_id = conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by) VALUES ('evil-link.com', 'evil-link.com', ?, 'manual')",
        (STAMP,),
    ).lastrowid
    for type_, value in (("dns_a", {"records": ["1.2.3.4"]}), ("in_feed", {"listed": listed, "feeds": ["openphish"]})):
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, ?, ?, 'test', ?, 'ok')",
            (domain_id, type_, json.dumps(value), STAMP),
        )
    conn.execute(
        "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (1, 'dns_a', ?, 'test', ?, 'ok')",
        (json.dumps({"records": ["1.2.3.4"]}), STAMP),
    )  # the low domain resolves to the same IP
    conn.commit()
    return domain_id


def test_new_edge_to_a_listed_domain_reassesses_the_low_neighbour_with_r4(tmp_path, monkeypatch):
    settings, state = _setup(tmp_path, monkeypatch)
    state["dns_ok"] = True  # the neighbour's recheck sees the same IP
    domain_id = _listed_neighbour(tmp_path)

    asyncio.run(
        db.run(lambda conn: worker._reassess(conn, domain_id, "evil-link.com", settings, STAMP) and conn.commit())
    )  # the listed domain was just assessed

    assert len(_due_jobs(tmp_path, "recheck")) == 1
    assert asyncio.run(worker.process_next(settings, None)) is True
    last = json.loads(
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT components_json FROM assessments WHERE domain_id = 1 ORDER BY id DESC LIMIT 1")
        .fetchone()[0]
    )
    assert "+1.5 linked to a domain in a phishing list" in last["breakdown"]


def test_unlisted_neighbour_queues_nothing(tmp_path, monkeypatch):
    settings, state = _setup(tmp_path, monkeypatch)
    state["dns_ok"] = True
    domain_id = _listed_neighbour(tmp_path, listed=False)

    asyncio.run(
        db.run(lambda conn: worker._reassess(conn, domain_id, "evil-link.com", settings, STAMP) and conn.commit())
    )

    assert _due_jobs(tmp_path, "recheck") == []


def test_scam_verdict_queues_recheck_for_linked_low_domains(tmp_path, monkeypatch):
    settings, _ = _setup(tmp_path, monkeypatch)
    domain_id = _listed_neighbour(tmp_path, listed=False)

    asyncio.run(db.run(worker.recheck_neighbours, "evil-link.com", settings))

    assert domain_id and len(_due_jobs(tmp_path, "recheck")) == 1
