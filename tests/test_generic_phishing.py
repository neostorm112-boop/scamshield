"""Brandless phishing : verdict, CT name gate, snapshot order, card headline."""

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import yaml

from scamshield.config import CONFIG_DIR, load_brands
from scamshield.contracts import Candidate, Ctx, FactRow
from scamshield.enrich.lookalike import generic_name
from scamshield.scoring import assess

NOW = datetime.fromisoformat("2026-11-20T10:00:00+00:00")
STAMP = NOW.isoformat().replace("+00:00", "Z")
BRANDS = load_brands(Path("config/brands.yaml"))
SCORING = yaml.safe_load((CONFIG_DIR / "scoring.yaml").read_text(encoding="utf-8"))
GENERIC_FACT = {
    "brand": None,
    "label": "x",
    "method": "generic_name",
    "restricted_zone": False,
    "context": "name",
    "context_words": [],
    "mode": "generic",
    "tld": "top",
    "lure": "login",
}


def _facts(age_days, page=None, asks=None, cert_days=None):
    rows = []

    def add(type_, value, status="ok"):
        rows.append(FactRow(type_, value, "test", None, STAMP, status, id=len(rows) + 1))

    add("lookalike", GENERIC_FACT)
    add("dns_a", {"records": ["1.2.3.4"]})
    add("ip_asn", {}, "missing")
    add("in_feed", {"listed": False})
    add(
        "created_at",
        {"date": (NOW - timedelta(days=age_days)).isoformat()} if age_days is not None else {},
        "ok" if age_days is not None else "missing",
    )
    add(
        "certs",
        {"first_issued": (NOW - timedelta(days=cert_days)).isoformat()} if cert_days is not None else {},
        "ok" if cert_days is not None else "missing",
    )
    add("snapshot_page", page or {"title": "Sign in", "text": "x"})
    if asks:
        add("snapshot_form", {"fields": [], "asks": asks})
    return rows


def _assess(facts, fqdn="verify-x.top"):
    return assess(fqdn, facts, [], None, [], BRANDS, SCORING)


def test_young_domain_with_card_form_is_queued_with_a_plain_reason():
    result = _assess(_facts(3, asks=["card", "otp"]))
    assert result.components["band"] == "GRAY" and result.state == "REVIEW" and "GENERIC_PHISHING" in result.flags
    assert result.components["reason"].startswith("Brand not identified") and "card" in result.components["reason"]


def test_exfil_alone_and_unknown_age_with_fresh_certificate_are_queued():
    assert (
        "GENERIC_PHISHING" in _assess(_facts(3, page={"title": "x", "text": "x", "exfil": ["api.telegram.org"]})).flags
    )
    assert "GENERIC_PHISHING" in _assess(_facts(None, asks=["otp"], cert_days=2)).flags
    assert (
        "GENERIC_PHISHING" not in _assess(_facts(3, asks=["password"])).flags
    )  # a password form alone: every casino / forum login


def test_old_domain_parked_page_no_form_or_unknown_age_are_not_queued():
    for facts in (
        _facts(400, asks=["card"]),
        _facts(3, page={"title": "x", "text": "", "parked": "sedo"}),
        _facts(3),
        _facts(None, asks=["card"]),
    ):
        result = _assess(facts)
        assert "GENERIC_PHISHING" not in result.flags
        assert result.components["band"] != "GRAY"


def test_official_domain_is_never_generic():
    assert _assess(_facts(3, asks=["card"]), "rta.ae").state == "OFFICIAL"


def test_name_gate_strong_word_passes_weak_word_needs_a_second_sign():
    assert generic_name("secure-login-x.top", SCORING, [])["lure"] == "login"
    assert generic_name("verify.abc.top", SCORING, [])["apex"] == "abc.top"
    assert (
        generic_name("verify.abc.top", SCORING, [])["host"] == "verify.abc.top"
    )  # the page lives on the lure subdomain
    assert generic_name("www.verify-x.top", SCORING, [])["host"] == "verify-x.top"
    assert generic_name("pay.abc.top", SCORING, []) is None  # weak word alone
    assert generic_name("bank.top", SCORING, []) is None
    assert generic_name("pay-abc.top", SCORING, [])  # weak word + hyphen
    assert generic_name("pay4abc.top", SCORING, []) is None  # no token split: not the word "pay"
    assert generic_name("pay-x9.top", SCORING, [])  # weak word + digit
    assert generic_name("secure-bank.top", SCORING, [])  # two weak words
    assert generic_name("garden-shop.top", SCORING, []) is None  # no lure word
    assert generic_name("login-x.com", SCORING, []) is None  # TLD not cheap
    assert generic_name("autodiscover.login-x.top", SCORING, []) is None
    assert generic_name("login-x.pages.dev", SCORING, []) is None
    assert generic_name("login-x.example.top", SCORING, ["example.top"]) is None  # shared_infra host suffix


def test_name_gate_reduces_www_and_generic_labels_to_the_apex():
    assert generic_name("www.verify-x.top", SCORING, [])["apex"] == "verify-x.top"
    assert generic_name("cdn.verify-x.top", SCORING, [])["apex"] == "verify-x.top"
    assert generic_name("www.abc.top", SCORING, []) is None  # the label is not a lure word
    assert generic_name("www.pay.abc.top", SCORING, []) is None


def _tile_ctx(monkeypatch, names, budget):
    from scamshield.connectors import ct_tiled
    from tests.test_ct_tiled import _Budget, _Response

    class Http:
        async def get(self, url, **kwargs):
            if url.endswith("/checkpoint"):
                return _Response(200, f"log.example\n{len(names)}\nhash\n")
            return _Response(
                200,
                "\n".join(json.dumps({"Timestamp": 1760000000000 + i, "DNS": [name]}) for i, name in enumerate(names)),
            )

    scoring = {**SCORING, "generic": {**SCORING["generic"], "budget_per_hour": budget}}
    settings = SimpleNamespace(
        brands=[],
        sources={"ct_tiled": SimpleNamespace(extra={"max_lag_minutes": 10**9, "logs": ["https://ct.example"]})},
        scoring=scoring,
        shared_infra={},
        secrets={},
    )
    monkeypatch.setattr(
        ct_tiled,
        "match",
        lambda name, brands: {"brand": "rta", "method": "x", "score": 1} if name == "rta-login.top" else None,
    )
    monkeypatch.setitem(ct_tiled._generic, "hour", "")
    monkeypatch.setitem(ct_tiled._generic, "dropped", 0)
    monkeypatch.setitem(ct_tiled._generic, "reported", 0)
    return ct_tiled, Ctx(settings, Http(), None, _Budget(), "auto", lambda: "2026-11-19T08:00:00Z")


def test_step_one_slot_per_apex_and_brand_hits_never_spend_or_wait(monkeypatch):
    names = [
        "verify-a.top",
        "www.verify-a.top",
        "verify-a.top",
        "rta-login.top",
        "verify-b.top",
        "verify-c.top",
        "kyc-d.top",
        "dubai.aeizt.top",
    ]
    ct_tiled, ctx = _tile_ctx(monkeypatch, names, 2)
    step = asyncio.run(ct_tiled._step("0", 256, ctx, "https://ct.example"))
    values = [c.value for c in step.batch.candidates]
    assert values == [
        "verify-a.top",
        "rta-login.top",
        "verify-b.top",
        "dubai.aeizt.top",
    ]  # a-repeats took one slot; the brand hit and the smishing name took none; c and d dropped
    assert ct_tiled._generic["taken"] == 2 and ct_tiled._generic["dropped"] == 2


def test_dropped_count_is_handed_out_once_across_logs(monkeypatch):
    ct_tiled, ctx = _tile_ctx(monkeypatch, ["verify-a.top", "verify-b.top", "verify-c.top"], 1)
    asyncio.run(ct_tiled._step("0", 256, ctx, "https://ct.example"))
    assert ct_tiled._dropped_unreported() == 2
    assert ct_tiled._dropped_unreported() == 0


def test_name_gate_budget_resets_each_hour(monkeypatch):
    ct_tiled, ctx = _tile_ctx(monkeypatch, [], 1)
    assert [ct_tiled._generic_slot(ctx, a) for a in ("a.top", "a.top", "b.top")] == [True, False, False]
    later = Ctx(ctx.settings, None, None, None, "auto", lambda: "2026-11-19T09:00:00Z")
    assert ct_tiled._generic_slot(later, "b.top") is True


def _db(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    with TestClient(create_app(background=False)):
        pass
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.row_factory = sqlite3.Row
    return conn


def test_generic_candidate_stores_lookalike_fact_and_lower_priority(tmp_path, monkeypatch):
    from scamshield import intake

    conn = _db(tmp_path, monkeypatch)
    intake._store(
        conn,
        [Candidate("verify-x.top", "ct_tiled", STAMP, "LIVE", {"log": "l", **GENERIC_FACT})],
        "ct_tiled",
        None,
        3600,
    )
    assert (
        json.loads(conn.execute("SELECT value_json FROM facts WHERE type = 'lookalike'").fetchone()[0])["method"]
        == "generic_name"
    )
    assert conn.execute("SELECT priority FROM jobs").fetchone()[0] == intake.GENERIC_PRIORITY


def test_generic_names_are_snapshotted_after_uae_brand_gray_low(tmp_path, monkeypatch):
    from scamshield import snapshot

    conn = _db(tmp_path, monkeypatch)
    for name, seen, kind in [
        ("brand.top", "2026-11-20T10:00:00Z", "smishing_pattern"),
        ("login-new.top", "2026-11-20T11:00:00Z", "generic_name"),
    ]:
        domain_id = conn.execute(
            "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state) VALUES (?, ?, ?, 'ct_tiled', 'REVIEW')",
            (name, name, seen),
        ).lastrowid
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, 'dns_a', ?, 'dns', ?, 'ok')",
            (domain_id, json.dumps({"records": ["198.51.100.8"]}), STAMP),
        )
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, 'lookalike', ?, 'ct_tiled', ?, 'ok')",
            (domain_id, json.dumps({"method": kind}), STAMP),
        )
        conn.execute(
            "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) VALUES (?, 'v', 0.3, 1, 'REVIEW', '[\"GRAY_LOW\"]', '{}', '[]', ?)",
            (domain_id, STAMP),
        )
    conn.commit()
    assert snapshot._next_auto(conn) == "brand.top"  # older, but a UAE-pattern hit goes before the newer brandless one


def test_card_headline_without_brand():
    from scamshield.web import view

    facts = [
        {
            "id": 1,
            "type": "snapshot_form",
            "value": {"fields": [], "asks": ["card"]},
            "status": "ok",
            "source": "snapshot",
            "fetched_at": STAMP,
            "data_mode": "LIVE",
            "error": None,
        }
    ]
    assessment = {
        "flags": ["GENERIC_PHISHING", "GRAY"],
        "components": {"reason": "Brand not identified, but the domain is new and page asks for card"},
        "at": STAMP,
    }
    ctx = view.case_context(
        {"fqdn": "verify-x.top", "brand_id": None, "state": "REVIEW", "risk_score": 0.5},
        facts,
        assessment,
        None,
        {},
        [],
        {},
        NOW,
    )
    assert ctx["headline"] == "Phishing, brand not identified" and ctx["sentence"].startswith(
        "Phishing, brand not identified"
    )
    assert ctx["reasons"][0]["text"].startswith("Brand not identified")


SW_JOB = {
    "title": "CAREEM Global | Ajira UAE",
    "text": "WhatsApp: +971 50 000 0000\nAjira za UAE na Safari za Dubai\nTafuta Kazi UAE, visa, tiketi",
}
CAREEM_LOOK = {
    **GENERIC_FACT,
    "brand": "careem",
    "label": "careemglobal",
    "method": "token",
    "position": "registrable",
    "context": "none",
    "mode": "ct",
}


def _careem(page):
    facts = _facts(2, page=page, asks=[])
    facts[0] = FactRow("lookalike", CAREEM_LOOK, "test", None, STAMP, "ok", id=1)
    return _assess(facts, "careemglobal.com")


def test_job_offer_with_messenger_lifts_a_brand_domain_above_gray():
    assert _careem({"title": "x", "text": "x"}).components["band"] == "GRAY"
    result = _careem(SW_JOB)
    assert result.components["band"] == "FURTHER" and any(
        "jobs or visas" in line for line in result.components["breakdown"]
    )


def test_job_offer_without_messenger_or_messenger_without_job_scores_nothing():
    for text in (
        "Vacancy: apply by email, jobs@x.top",
        "Shop now. Order via WhatsApp: +971 50 000 0000",
        "We accept Visa card. wa.me/971500000000",
    ):
        assert "jobs or visas" not in " ".join(_careem({"title": "x", "text": text}).components["breakdown"])


def test_arabic_and_other_languages_and_link_forms():
    for text in (
        "وظائف في دبي\nواتساب: +971 50 000 0000",
        "вакансия курьера, t.me/hr_dubai",
        "Trabaho sa Dubai https://wa.me/971500000000",
        "Naukri in UAE, telegram @uaehire",
    ):
        assert "jobs or visas" in " ".join(_careem({"title": "x", "text": text}).components["breakdown"]), text


def test_no_brand_job_offer_needs_a_young_domain():
    assert _assess(_facts(3, page=SW_JOB)).components["reason"].startswith("Brand not identified")
    assert _assess(_facts(3, page=SW_JOB)).components["band"] == "GRAY"
    assert _assess(_facts(400, page=SW_JOB)).components["band"] != "GRAY"


def test_job_offer_is_the_first_reason_on_the_card():
    from datetime import UTC, datetime

    from scamshield.web import view

    fact = {
        "id": 7,
        "type": "snapshot_page",
        "status": "ok",
        "source": "snapshot",
        "fetched_at": "2026-11-22T10:00:00Z",
        "data_mode": "LIVE",
        "value": {
            "title": "CAREEM GLOBAL SERVICES",
            "text": "Ajira za UAE na Safari za Dubai. WhatsApp: +971 50 000 0000",
            "redirects": [],
        },
    }
    line = view._fact_line(fact, {}, datetime(2026, 11, 22, tzinfo=UTC))
    assert line["rank"] == 0 and "WhatsApp" in line["reason"]


def test_brand_recheck_keeps_a_brandless_name(tmp_path, monkeypatch):
    import sqlite3

    from scamshield import config, db, worker
    from scamshield.enrich.lookalike import fact_value, generic_name

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    settings = config.load()
    db.init(settings.db_path)
    conn = sqlite3.connect(settings.db_path)
    conn.execute(
        "INSERT INTO domains (id, fqdn, registrable, first_seen_at, found_by, last_seen_at, state, data_mode) VALUES (1, 'login.vodka-5bi.top', 'vodka-5bi.top', 'x', 'ct_tiled', 'x', 'REVIEW', 'LIVE')"
    )
    value = {"log": "https://ct.example", **fact_value(generic_name("login.vodka-5bi.top", settings.scoring, []))}
    conn.execute(
        "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, data_mode) VALUES (1, 'lookalike', ?, 'ct_tiled', 'x', 'x', 'ok', 'LIVE')",
        (json.dumps(value),),
    )
    worker._recheck_brand(conn, 1, "login.vodka-5bi.top", settings, "t", 5)
    assert (
        conn.execute("SELECT count(*) FROM facts WHERE source = 'brand_check'").fetchone()[0] == 0
    )  # was: a "brand rule no longer matches" fact -> NOISE
