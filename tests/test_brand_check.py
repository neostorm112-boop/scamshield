import asyncio
import dataclasses
import json
import sqlite3
from datetime import UTC, datetime, timedelta

import httpx
from fastapi.testclient import TestClient

from scamshield import config, db, intake, live, runtime, worker
from scamshield.connectors import tavily_search


def _setup(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def none(fqdn, ctx):
        return []

    for name in ("dns", "asn", "rdap", "certspotter", "feed_match"):
        monkeypatch.setattr(getattr(worker, name), "run", none)
    return config.load()


def _paste_and_check(settings, fqdn):
    asyncio.run(intake.submit(fqdn, "manual", [], 10))
    assert asyncio.run(worker.process_next(settings, None)) is True


def _lookalike(tmp_path, fqdn):
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    rows = conn.execute(
        "SELECT f.value_json, d.brand_id FROM facts f JOIN domains d ON d.id = f.domain_id WHERE d.fqdn = ? AND f.type = 'lookalike'",
        (fqdn,),
    ).fetchall()
    return [(json.loads(v)["brand"], b) for v, b in rows]


def test_pasted_fake_gets_brand_fact_and_header(tmp_path, monkeypatch):
    from scamshield.app import create_app

    settings = _setup(tmp_path, monkeypatch)
    fqdn = "aramex-1f3a9c.ingress-earth.ewp.live"
    _paste_and_check(settings, fqdn)

    assert _lookalike(tmp_path, fqdn) == [("aramex", "aramex")]
    with TestClient(create_app(background=False)) as client:
        assert "Looks like Aramex" in client.get(f"/d/{fqdn}").text


def test_search_result_gets_brand_fact(tmp_path, monkeypatch):
    settings = _setup(tmp_path, monkeypatch)

    class Http:
        async def post(self, url, **kwargs):
            return httpx.Response(200, json={"results": [{"url": "https://darb-toll-pay.com/x", "title": "t"}]})

    now = datetime(2026, 11, 19, 8, 0, tzinfo=UTC).isoformat().replace("+00:00", "Z")
    ctx = dataclasses.replace(runtime.make_ctx(settings, Http(), "manual"), now=lambda: now)
    asyncio.run(tavily_search.search(ctx, "darb"))

    conn = sqlite3.connect(tmp_path / "scamshield.db")
    assert (
        conn.execute(
            "SELECT count(*) FROM facts f JOIN domains d ON d.id = f.domain_id WHERE d.fqdn = 'darb-toll-pay.com' AND f.type = 'lookalike'"
        ).fetchone()[0]
        == 1
    )
    asyncio.run(worker.process_next(settings, None))
    assert _lookalike(tmp_path, "darb-toll-pay.com") == [("darb", "darb")]


def test_darb_portal_of_its_operator_is_official(tmp_path, monkeypatch):
    """Q Mobility runs Darb: darb.qmobility.ae was once wrongly used as a golden fake."""
    settings = _setup(tmp_path, monkeypatch)
    _paste_and_check(settings, "darb.qmobility.ae")

    assert _lookalike(tmp_path, "darb.qmobility.ae") == []
    assert (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT state FROM domains WHERE fqdn = 'darb.qmobility.ae'")
        .fetchone()[0]
        == "OFFICIAL"
    )


def test_official_domain_stays_official_without_brand_fact(tmp_path, monkeypatch):
    settings = _setup(tmp_path, monkeypatch)
    _paste_and_check(settings, "rta.ae")

    assert _lookalike(tmp_path, "rta.ae") == []
    assert (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT state FROM domains WHERE fqdn = 'rta.ae'")
        .fetchone()[0]
        == "OFFICIAL"
    )


def test_oldest_queued_ignores_jobs_waiting_for_the_future(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    now = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    conn = db._conn()
    later = (now + timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    conn.execute(
        "INSERT INTO jobs (kind, target, payload_json, idem_key, run_after, created_at) VALUES ('recheck', 'a.com', '{}', 'k1', ?, '2026-11-19T12:00:00Z')",
        (later,),
    )
    conn.commit()
    assert live.health(conn, now=now)["queue"]["oldest_queued_s"] is None
    conn.execute(
        "INSERT INTO jobs (kind, target, payload_json, idem_key, created_at) VALUES ('check_domain', 'b.com', '{}', 'k2', '2026-11-20T11:00:00Z')"
    )
    conn.commit()
    assert live.health(conn, now=now)["queue"]["oldest_queued_s"] == 3600


def test_identical_link_reasons_are_grouped():
    from scamshield.web.view import link_reasons

    edge = lambda b, ids: {
        "a": "x.com",
        "b": b,
        "sentence": "Same name server",
        "level": "weak",
        "evidence": [{"id": i} for i in ids],
    }
    out = link_reasons(
        [edge("b.com", [110, 1]), edge("c.com", [111, 1]), {**edge("d.com", [112]), "sentence": "Other"}]
    )

    assert [(r["sentence"], [e["id"] for e in r["evidence"]]) for r in out] == [
        ("Same name server", [110, 1, 111]),
        ("Other", [112]),
    ]


def _intake_hit(settings, fqdn, source="ct_tiled", mode="ct", found_by="ct_tiled"):
    """Intake evidence as stored before a rule change: the hit current rules give, or a stale `dewa` one when they give none."""
    from scamshield.contracts import Fact
    from scamshield.enrich import lookalike

    hit = lookalike.match(fqdn, settings.brands, mode)
    value = (
        lookalike.fact_value(hit)
        if hit
        else {
            "brand": "dewa",
            "keyword": "dewa",
            "label": "dewa",
            "score": 1.0,
            "method": "token",
            "position": "registrable",
            "restricted_zone": False,
            "context": "none",
            "context_words": [],
            "tokens": [],
            "mode": mode,
        }
    )
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    asyncio.run(intake.submit(fqdn, found_by, [Fact("lookalike", value, source, now, now, "ok")], 10))
    return value


def _state(tmp_path, fqdn):
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    state, comp = conn.execute(
        "SELECT d.state, a.components_json FROM domains d JOIN assessments a ON a.domain_id = d.id WHERE d.fqdn = ? ORDER BY a.id DESC LIMIT 1",
        (fqdn,),
    ).fetchone()
    return state, json.loads(comp)


def _job_lookalikes(tmp_path):
    return (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT count(*) FROM facts WHERE type = 'lookalike' AND job_id IS NOT NULL")
        .fetchone()[0]
    )


def test_stale_intake_brand_hit_is_superseded_by_current_rules(tmp_path, monkeypatch):
    settings = _setup(tmp_path, monkeypatch)
    fqdn = "sembilan-dewa.xyz"
    _intake_hit(settings, fqdn)
    assert asyncio.run(worker.process_next(settings, None)) is True

    state, comp = _state(tmp_path, fqdn)
    assert (
        state == "NOISE"
        and comp["reason"] == f"brand rule no longer matches (rule_version {settings.scoring['rule_version']})"
    )
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    assert [
        r[0]
        for r in conn.execute(
            "SELECT f.status FROM facts f JOIN domains d ON d.id = f.domain_id WHERE d.fqdn = ? AND f.type = 'lookalike' ORDER BY f.id",
            (fqdn,),
        )
    ] == ["ok", "missing"]  # history kept


def test_unchanged_brand_hit_gives_same_result_and_no_new_fact(tmp_path, monkeypatch):
    settings = _setup(tmp_path, monkeypatch)
    fqdn = "aramex-help.com"
    _intake_hit(settings, fqdn)
    asyncio.run(worker.process_next(settings, None))
    before = _state(tmp_path, fqdn)
    asyncio.run(intake.submit(fqdn, "manual", [], 10))
    asyncio.run(worker.process_next(settings, None))

    assert _state(tmp_path, fqdn) == before and before[0] != "NOISE"
    assert _job_lookalikes(tmp_path) == 0


def test_search_brand_evidence_survives_rule_change(tmp_path, monkeypatch):
    settings = _setup(tmp_path, monkeypatch)
    fqdn = "sembilan-dewa.xyz"
    _intake_hit(settings, fqdn, source="tavily", found_by="tavily")
    asyncio.run(worker.process_next(settings, None))

    assert _job_lookalikes(tmp_path) == 0
    assert "brand rule no longer matches" not in _state(tmp_path, fqdn)[1]["reason"]
