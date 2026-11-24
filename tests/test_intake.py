import asyncio
import sqlite3

from scamshield import db
from scamshield.contracts import Candidate, Fact


def test_intake_persists_ct_candidate_and_cursor(tmp_path):
    from scamshield import intake

    database = tmp_path / "scamshield.db"
    db.init(str(database))
    candidate = Candidate(
        "e1isalat-pay.com", "ct_tiled", "2026-11-19T08:00:00Z", "LIVE", {"brand": "etisalat", "score": 0.8}
    )

    asyncio.run(intake.store_candidates([candidate], "https://ct.example", "42", 86400))

    conn = sqlite3.connect(database)
    domain = conn.execute("SELECT fqdn, brand_id, found_by, data_mode FROM domains").fetchone()
    cursor = conn.execute("SELECT cursor FROM cursors WHERE connector = ?", ("https://ct.example",)).fetchone()
    assert domain == ("e1isalat-pay.com", "etisalat", "ct_tiled", "LIVE")
    assert cursor == ("42",)


def test_submit_subdomain_gets_registrable_and_one_job(tmp_path):
    from scamshield import intake

    database = tmp_path / "scamshield.db"
    db.init(str(database))

    asyncio.run(intake.submit("login.rta-pay.com", "manual", [], 10))
    asyncio.run(intake.submit("login.rta-pay.com", "manual", [], 10))

    conn = sqlite3.connect(database)
    assert conn.execute("SELECT fqdn, registrable FROM domains").fetchall() == [("login.rta-pay.com", "rta-pay.com")]
    assert conn.execute("SELECT kind, target, priority FROM jobs").fetchall() == [
        ("check_domain", "login.rta-pay.com", 10)
    ]


def test_ct_candidate_is_enriched_by_worker(tmp_path, monkeypatch):
    from scamshield import config, intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    database = tmp_path / "scamshield.db"
    db.init(str(database))

    async def dns_run(fqdn, ctx):
        return [Fact("dns_a", {"records": ["93.184.216.34"]}, "dns", None, "2026-11-19T08:00:00Z", "ok")]

    async def asn_run(fqdn, ctx):
        return [Fact("ip_asn", {"ip": "93.184.216.34", "asn": 15133}, "asn", None, "2026-11-19T08:00:00Z", "ok")]

    async def rdap_run(fqdn, ctx):
        return [Fact("created_at", {}, "rdap", None, "2026-11-19T08:00:00Z", "missing")]

    async def certs_run(fqdn, ctx):
        return []

    monkeypatch.setattr(worker.dns, "run", dns_run)
    monkeypatch.setattr(worker.asn, "run", asn_run)
    monkeypatch.setattr(worker.rdap, "run", rdap_run)
    monkeypatch.setattr(worker.certspotter, "run", certs_run)
    monkeypatch.setattr(worker.feed_match, "run", certs_run)
    candidate = Candidate(
        "login.e1isalat-pay.com", "ct_tiled", "2026-11-19T08:00:00Z", "LIVE", {"brand": "etisalat", "score": 0.8}
    )

    asyncio.run(intake.store_candidates([candidate], "https://ct.example", "1", 86400))
    assert asyncio.run(worker.process_next(config.load(), None)) is True

    conn = sqlite3.connect(database)
    types = {row[0] for row in conn.execute("SELECT type FROM facts")}
    assert {"lookalike", "dns_a", "ip_asn", "created_at"} <= types
    assert conn.execute("SELECT registrable, state FROM domains").fetchone()[0] == "e1isalat-pay.com"
    assert conn.execute("SELECT count(*) FROM assessments").fetchone()[0] == 1
    assert conn.execute("SELECT status FROM jobs").fetchone()[0] == "done"


def test_same_ct_domain_twice_gives_one_job_and_one_lookalike_fact(tmp_path):
    from scamshield import intake

    database = tmp_path / "scamshield.db"
    db.init(str(database))
    first = Candidate(
        "e1isalat-pay.com", "ct_tiled", "2026-11-19T08:00:00Z", "LIVE", {"brand": "etisalat", "score": 0.8}
    )
    again = Candidate(
        "e1isalat-pay.com", "ct_tiled", "2026-11-19T09:30:00Z", "LIVE", {"brand": "etisalat", "score": 0.8}
    )

    asyncio.run(intake.store_candidates([first], "https://ct.example", "1", 86400))
    asyncio.run(intake.store_candidates([again], "https://ct.example", "2", 86400))

    conn = sqlite3.connect(database)
    assert conn.execute("SELECT count(*) FROM jobs").fetchone()[0] == 1
    assert conn.execute("SELECT count(*) FROM facts WHERE type = 'lookalike'").fetchone()[0] == 1
    assert conn.execute("SELECT last_seen_at FROM domains").fetchone()[0] == "2026-11-19T09:30:00Z"


def test_manual_check_after_ct_always_queues_fresh_job(tmp_path):
    from scamshield import intake

    database = tmp_path / "scamshield.db"
    db.init(str(database))
    candidate = Candidate(
        "e1isalat-pay.com", "ct_tiled", "2026-11-19T08:00:00Z", "LIVE", {"brand": "etisalat", "score": 0.8}
    )

    asyncio.run(intake.store_candidates([candidate], "https://ct.example", "1", 86400))
    asyncio.run(intake.submit("e1isalat-pay.com", "manual", [], 10))

    assert sqlite3.connect(database).execute("SELECT count(*) FROM jobs").fetchone()[0] == 2


def test_store_writes_full_lookalike_value_from_match(tmp_path):
    import json
    from pathlib import Path

    from scamshield import intake
    from scamshield.config import load_brands
    from scamshield.connectors import feeds
    from scamshield.enrich import lookalike
    from scamshield.enrich.lookalike import match

    database = tmp_path / "scamshield.db"
    db.init(str(database))
    brands = load_brands(Path("config/brands.yaml"))
    ct_hit = match("e1isalat-pay.com", brands)
    candidate = Candidate("e1isalat-pay.com", "ct_tiled", "2026-11-19T08:00:00Z", "LIVE", lookalike.fact_value(ct_hit))
    [feed_candidate] = feeds._lookalikes(["rta.dogestocks.com"], brands, "feeds", "2026-11-19T08:00:00Z", {})

    asyncio.run(intake.store_candidates([candidate, feed_candidate], "https://ct.example", None, 86400))

    rows = {
        fqdn: json.loads(value)
        for fqdn, value in sqlite3.connect(database).execute(
            "SELECT d.fqdn, f.value_json FROM facts f JOIN domains d ON d.id = f.domain_id WHERE f.type = 'lookalike'"
        )
    }
    assert (
        rows["e1isalat-pay.com"]["method"],
        rows["e1isalat-pay.com"]["position"],
        rows["e1isalat-pay.com"]["mode"],
    ) == ("homoglyph", "registrable", "ct")
    assert rows["e1isalat-pay.com"]["context_words"] == ["pay"]
    assert (
        rows["rta.dogestocks.com"]["position"],
        rows["rta.dogestocks.com"]["context"],
        rows["rta.dogestocks.com"]["mode"],
    ) == ("subdomain", "none", "feed")
