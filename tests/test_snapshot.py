import asyncio
import json
import os
import subprocess
from pathlib import Path

import pytest

from scamshield import config, db, intake, netsafe, snapshot
from scamshield.contracts import FactRow
from scamshield.scoring import assess
from scamshield.tools import build_brand_refs
from tests import snapshot_site as site


@pytest.fixture(scope="module")
def server():
    srv = site.serve()
    yield srv
    srv.shutdown()


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    s = config.load()
    db.init(s.db_path)
    monkeypatch.setattr(snapshot, "REFS_PATH", tmp_path / "refs.json")
    return s


def _grab(settings, server, host, path, tmp_path, **dns):
    url = f"http://{host}:{server.server_port}{path}"
    return asyncio.run(snapshot.capture(url, settings, tmp_path / "out", site.fake_check, site.fake_dns(**dns)))


def test_page_gives_picture_text_and_form_fields_without_typing(settings, server, tmp_path):
    result = _grab(settings, server, "phish.test", "/phish", tmp_path)
    assert result.status == "ok"
    assert result.title == "Secure payment" and "Pay your fine now" in result.visible_text
    assert [f["name"] for f in result.form_fields] == ["card_number", "cvv", "otp", "pw"]
    assert Path(result.screenshot_path).read_bytes()[:4] == b"\x89PNG"
    assert len(result.hashes["page"]) == 16 and len(result.hashes["logo"]) == 16
    assert snapshot.classify_asks(result.form_fields) == ["card", "cvv", "otp", "password"]


@pytest.mark.parametrize(
    ("path", "dns", "reason"),
    [
        ("/ws", {}, "private address blocked"),
        ("/big", {}, "page larger than 10 MB"),
        ("/download", {}, "download blocked"),
        ("/autodownload", {}, "download blocked"),
        ("/redirect", {}, "private address blocked"),
        ("/rebind", {"rebind.test": [[site.PUBLIC], ["127.0.0.1"]]}, "private address blocked"),
    ],
)
def test_dangerous_pages_are_stopped(settings, server, tmp_path, path, dns, reason):
    settings.sources["snapshot"].extra["max_bytes"] = 10_000_000
    host = "rebind.test" if path == "/rebind" else "phish.test"
    dns = {"phish.test": [[site.PUBLIC]], **dns}
    result = _grab(settings, server, host if path != "/rebind" else "phish.test", path, tmp_path, **dns)
    assert (result.status, result.reason) == ("blocked", reason)
    assert snapshot._message(result, 15) == f"Snapshot stopped for safety: {reason}."


def test_socket_to_a_public_host_is_allowed_and_the_form_is_read(settings, server, tmp_path):
    result = _grab(settings, server, "phish.test", "/wspublic", tmp_path, **{"phish.test": [[site.PUBLIC]]})
    assert (result.status, result.reason) == ("ok", None)
    assert snapshot.classify_asks(result.form_fields) == ["card", "cvv", "otp", "password"]


@pytest.mark.parametrize(("path", "feature"), [("/rtc", "RTCPeerConnection"), ("/worker", "Worker")])
def test_webrtc_and_workers_are_refused_but_the_page_is_still_read(settings, server, tmp_path, path, feature):
    result = _grab(settings, server, "phish.test", path, tmp_path)
    assert (result.status, result.disabled) == ("ok", [feature]) and result.screenshot_path


def test_script_redirector_is_followed_to_the_real_page(settings, server, tmp_path):
    result = _grab(settings, server, "phish.test", "/cloak", tmp_path)
    assert (
        result.status == "ok" and result.final_url.endswith("/phish") and result.redirect_chain[-1].endswith("/phish")
    )
    assert snapshot.classify_asks(result.form_fields) == ["card", "cvv", "otp", "password"]


def test_parked_page_is_recognised(settings, server, tmp_path):
    assert (
        _grab(
            settings,
            server,
            "phish.test",
            "/parked",
            tmp_path,
            **{"phish.test": [[site.PUBLIC]], "park.parklogic.com": [[site.PUBLIC]]},
        ).parked
        == "parklogic.com"
    )
    assert _grab(settings, server, "phish.test", "/shop", tmp_path).parked is None
    assert (
        _grab(settings, server, "phish.test", "/stuffed", tmp_path).parked is None
    )  # markers in raw HTML and "jordan.com" are not parking


def test_parking_marker_rules():
    from scamshield.snapshot_runner import parked_marker

    assert parked_marker("x.ph", {"x.ph", "cdn.parklogic.com"}, "") == "parklogic.com"
    assert (
        parked_marker("talabat.eat", {"talabat.eat"}, "talabat.eat is parked free, courtesy of GoDaddy.com")
        == "is parked free"
    )
    assert parked_marker("shop.dan.com", {"shop.dan.com"}, "") is None  # a page on the parking company's own site
    assert parked_marker("x.example", {"jordan.com", "x.example"}, "Visit jordan.com") is None


def test_redirect_to_a_dead_host_keeps_the_page_we_had(settings, server, tmp_path):
    result = _grab(settings, server, "phish.test", "/cloakdead", tmp_path)
    assert (
        result.status == "ok"
        and "Pay your fine now" in result.visible_text
        and not result.final_url.startswith("chrome-error")
    )


def test_page_values_never_reach_the_evidence(settings, server, tmp_path):
    result = _grab(settings, server, "phish.test", "/fakeblocked", tmp_path)
    assert (result.status, result.disabled) == ("ok", [])


def test_worker_from_a_fresh_iframe_is_refused_too(settings, server, tmp_path):
    result = _grab(settings, server, "phish.test", "/iframeworker", tmp_path)
    assert (result.status, result.title, result.disabled) == ("ok", "refused:SecurityError", ["Worker"])


def test_size_stop_names_the_configured_limit(settings, server, tmp_path):
    settings.sources["snapshot"].extra["max_bytes"] = 5_000_000
    assert _grab(settings, server, "phish.test", "/big", tmp_path).reason == "page larger than 5 MB"
    settings.sources["snapshot"].extra["max_bytes"] = 40_000_000
    assert (
        _grab(settings, server, "phish.test", "/big", tmp_path).status == "ok"
    )  # an 11 MB official page (rta.ae) is not a safety stop


def test_private_link_is_refused_before_the_browser_starts(settings, tmp_path):
    result = asyncio.run(snapshot.capture("http://127.0.0.1/", settings, tmp_path / "o"))
    assert (result.status, result.reason) == ("blocked", "private address blocked")


def test_hung_page_is_killed_after_the_hard_limit(settings, server, tmp_path):
    settings.sources["snapshot"].extra["hard_kill_s"] = 3
    mine = [
        "pgrep",
        "-P",
        str(os.getpid()),
        "-f",
        "snapshot_runner",
    ]  # only our own children: a live app in the same checkout runs snapshots too
    before = subprocess.run(mine, capture_output=True, text=True, check=False).stdout.split()
    result = _grab(settings, server, "phish.test", "/hang", tmp_path)
    assert result.status == "timeout" and "killed after 3 s" in result.reason
    left = set(subprocess.run(mine, capture_output=True, text=True, check=False).stdout.split()) - set(before)
    assert not left


def _facts(*pairs):
    return [FactRow(t, v, "snapshot", None, "2026-11-20T10:00:00Z", "ok", id=i + 1) for i, (t, v) in enumerate(pairs)]


def _plain():
    return [
        ("dns_a", {"records": ["1.2.3.4"]}),
        ("ip_asn", {}),
        ("in_feed", {"listed": False}),
        ("created_at", {"date": "2026-11-18T00:00:00"}),
        ("certs", {}),
    ]


def test_brandless_domain_with_brand_logo_and_card_form_rises_above_gray_low(settings):
    base = _facts(*_plain())
    low = assess("secure-pay.example", base, [], None, [], settings.brands, settings.scoring)
    assert "GRAY_LOW" in low.flags
    raised = assess(
        "secure-pay.example",
        _facts(
            *_plain(),
            ("snapshot_brand", {"brand": "rta", "via": ["logo"]}),
            ("snapshot_form", {"fields": [], "asks": ["card", "otp"]}),
        ),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    assert "GRAY_LOW" not in raised.flags and raised.risk_score > low.risk_score
    text = " ".join(raised.components["breakdown"])
    assert (
        "page shows Roads and Transport Authority logo on a non-official domain" in text
        and "page asks for card, otp" in text
    )


def test_page_that_only_mentions_a_brand_name_is_weaker_than_its_logo(settings):
    name = assess(
        "x.example",
        _facts(*_plain(), ("snapshot_brand", {"brand": "rta", "via": ["name"]})),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    logo = assess(
        "x.example",
        _facts(*_plain(), ("snapshot_brand", {"brand": "rta", "via": ["logo"]})),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    assert 0 < name.components["B"] < logo.components["B"]


def test_logo_copy_on_other_domain_is_detected_but_official_page_is_not(settings, server, tmp_path):
    cfg = settings.scoring["snapshot"]
    official = _grab(settings, server, "official.test", "/official", tmp_path)
    refs = {
        "rta": [{"domain": "rta.ae", "page": official.hashes["page"], "logo": official.hashes["logo"], "favicon": None}]
    }
    phish = _grab(settings, server, "phish.test", "/phish", tmp_path)
    shop = _grab(settings, server, "shop.test", "/shop", tmp_path)
    shown = snapshot.brand_shown(
        phish.title, phish.visible_text, phish.hashes, "phish.test", settings.brands, refs, cfg
    )
    assert shown == {"brand": "rta", "via": ["logo"]}  # the nearly white page picture is no evidence
    assert (
        snapshot.brand_shown("", "", {"page": official.hashes["page"]}, "x.test", settings.brands, refs, cfg) is None
    )  # picture alone is not enough
    assert (
        snapshot.brand_shown(shop.title, shop.visible_text, shop.hashes, "shop.test", settings.brands, refs, cfg)
        is None
    )
    assert (
        snapshot.brand_shown(phish.title, phish.visible_text, phish.hashes, "rta.ae", settings.brands, refs, cfg)
        is None
    )
    arabic = [type(b)(**{**b.__dict__, "keywords": ["هيئة الطرق"]}) for b in settings.brands if b.id == "rta"]
    assert snapshot.brand_shown("هيئة الطرق والمواصلات", "", {}, "x.test", arabic, {}, cfg)["via"] == ["name"]


def test_ordinary_words_and_empty_pictures_do_not_make_a_brand(settings):
    cfg = settings.scoring["snapshot"]
    assert (
        snapshot.brand_shown(
            "Acme",
            "Offices in Dubai, United Arab Emirates. Open noon to five.",
            {},
            "acme.example",
            settings.brands,
            {},
            cfg,
        )
        is None
    )
    empty = {
        "tamm": [{"domain": "tamm.abudhabi", "page": "0000000000000000", "logo": "0000000000000000", "favicon": None}]
    }
    assert (
        snapshot.brand_shown("", "", {"page": "0" * 16, "logo": "0" * 16}, "old.example", settings.brands, empty, cfg)
        is None
    )
    assert (
        snapshot.usable_hash("0" * 16) is None
        and snapshot.usable_hash("ffffffffffffffff") is None
        and snapshot.usable_hash("0f0f0f0f0f0f0f0f")
    )


def test_favicon_hash_match(settings):
    refs = {"rta": [{"domain": "rta.ae", "page": None, "logo": None, "favicon": "ab" * 32}]}
    assert snapshot.brand_shown(
        "", "", {"favicon": "ab" * 32}, "x.example", settings.brands, refs, settings.scoring["snapshot"]
    )["via"] == ["favicon"]


def test_snapshot_is_stored_as_facts_and_lifts_the_domain(settings, server, tmp_path, monkeypatch):
    official = _grab(settings, server, "official.test", "/official", tmp_path)
    (tmp_path / "refs.json").write_text(
        json.dumps(
            {"brands": {"rta": [{"domain": "rta.ae", "page": None, "logo": official.hashes["logo"], "favicon": None}]}}
        )
    )
    asyncio.run(intake.submit("phish.test", "manual", [], 0))

    def prep(conn):
        did = conn.execute("SELECT id FROM domains WHERE fqdn = 'phish.test'").fetchone()[0]
        conn.execute(
            "INSERT INTO urls (domain_id, url, first_seen_at, source) VALUES (?, ?, '2026-11-20T00:00:00Z', 'test')",
            (did, f"http://phish.test:{server.server_port}/phish"),
        )
        conn.commit()

    asyncio.run(db.run(prep))
    monkeypatch.setattr(netsafe, "check_url", site.fake_check)
    real = snapshot.capture

    async def seam(url, s, out, check=site.fake_check, fake_dns=None):
        return await real(url, s, out, site.fake_check, site.fake_dns())

    monkeypatch.setattr(snapshot, "capture", seam)
    assert asyncio.run(snapshot.take(settings, "phish.test")).status == "ok"
    rows = asyncio.run(
        db.run(
            lambda c: [
                (r["type"], r["source"], r["status"])
                for r in c.execute("SELECT * FROM facts WHERE type LIKE 'snapshot%'")
            ]
        )
    )
    assert {t for t, *_ in rows} == {"snapshot_page", "snapshot_form", "snapshot_brand"} and {
        s for _, s, _ in rows
    } == {"snapshot"}
    case = asyncio.run(
        db.run(
            lambda c: c.execute(
                "SELECT brand_id, (SELECT count(*) FROM artifacts WHERE kind = 'screenshot') n FROM domains WHERE fqdn = 'phish.test'"
            ).fetchone()
        )
    )
    assert (case["brand_id"], case["n"]) == ("rta", 1)


def test_auto_snapshots_stop_at_the_hourly_budget(settings, monkeypatch):
    settings.sources["snapshot"].budget_per_hour = 2
    for name in ("a.example", "b.example", "c.example"):
        asyncio.run(intake.submit(name, "feeds", [], 0))

    def prep(conn):
        for (did,) in conn.execute("SELECT id FROM domains").fetchall():
            conn.execute("UPDATE domains SET state = 'REVIEW' WHERE id = ?", (did,))
            conn.execute(
                "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) VALUES (?, 'v', 0.1, 1, 'REVIEW', '[\"GRAY_LOW\"]', '{}', '[]', '2026-11-20T00:00:00Z')",
                (did,),
            )
            conn.execute(
                "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, 'dns_a', '{}', 'dns', '2026-11-20T00:00:00Z', 'ok')",
                (did,),
            )
        conn.commit()

    asyncio.run(db.run(prep))
    taken = []

    async def fake_take(s, fqdn, **_):
        taken.append(fqdn)
        await db.run(
            lambda c: (
                c.execute(
                    "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES ((SELECT id FROM domains WHERE fqdn = ?), 'snapshot_page', '{}', 'snapshot', 'x', 'ok')",
                    (fqdn,),
                ),
                c.commit(),
            )
        )

    monkeypatch.setattr(snapshot, "take", fake_take)
    results = [asyncio.run(snapshot.auto_once(settings)) for _ in range(3)]
    assert len(taken) == 2 and results[2] is None  # the third one is queued but the budget is used up


def test_brand_refs_script_snapshots_only_official_domains(settings, tmp_path):
    seen = []

    async def grab(url, s, out, max_bytes, max_requests):
        seen.append(url)
        return snapshot.SnapshotResult(
            "ok", None, url, [], "t", "", [], None, None, 0, {"page": "00" * 8, "logo": None, "favicon": None}
        )

    data = asyncio.run(build_brand_refs.build(settings, {"rta"}, tmp_path / "r.json", grab))
    assert (
        seen == ["https://rta.ae/"]
        and data["built_at"]
        and json.loads((tmp_path / "r.json").read_text())["brands"]["rta"][0]["domain"] == "rta.ae"
    )


def test_case_shows_the_picture_and_evidence_serves_only_stored_png(tmp_path, monkeypatch):
    import sqlite3

    from fastapi.testclient import TestClient

    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    shot = tmp_path / "s.png"
    shot.write_bytes(site.LOGO)
    with TestClient(create_app(background=False)) as client:
        conn = sqlite3.connect(tmp_path / "scamshield.db")
        conn.execute(
            "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score) VALUES ('x.example', 'x.example', '2026-11-20T08:00:00Z', 'feeds', 'REVIEW', 0.3)"
        )
        conn.execute(
            "INSERT INTO artifacts (domain_id, kind, path, sha256, bytes, captured_at) VALUES (1, 'screenshot', ?, 'h', 1, '2026-11-20T08:00:00Z')",
            (str(shot),),
        )
        conn.commit()
        page = client.get("/d/x.example").text
        assert 'src="/evidence/1"' in page and "captured" in page
        got = client.get("/evidence/1")
        assert got.headers["content-type"] == "image/png" and got.content[:4] == b"\x89PNG"
        assert client.get("/evidence/99").status_code == 404


def _case_client(tmp_path, monkeypatch, facts):
    import sqlite3

    from fastapi.testclient import TestClient

    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    shot = tmp_path / "s.png"
    shot.write_bytes(site.LOGO)
    client = TestClient(create_app(background=False))
    client.__enter__()
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score) VALUES ('x.example', 'x.example', '2026-11-20T08:00:00Z', 'feeds', 'REVIEW', 0.3)"
    )
    for kind, value, status, error in facts:
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, error) VALUES (1, ?, ?, 'snapshot', '2026-11-20T08:00:00Z', '2026-11-20T08:00:00Z', ?, ?)",
            (kind, json.dumps(value), status, error),
        )
    conn.execute(
        "INSERT INTO artifacts (domain_id, kind, path, sha256, bytes, captured_at) VALUES (1, 'screenshot', ?, 'h', 1, '2026-11-20T08:00:00Z')",
        (str(shot),),
    )
    conn.commit()
    return client


def test_snapshot_without_a_brand_still_opens_the_case(tmp_path, monkeypatch):
    client = _case_client(
        tmp_path, monkeypatch, [("snapshot_page", {"title": "Hello"}, "ok", None), ("snapshot_brand", {}, "ok", None)]
    )
    got = client.get("/d/x.example")
    assert got.status_code == 200 and "No brand seen on the page" in got.text


def test_case_shows_the_newest_snapshot_attempt_not_an_old_failure(tmp_path, monkeypatch):
    old = [("snapshot_page", {}, "error", "Snapshot not taken: page did not load in 15 s.")]
    client = _case_client(tmp_path, monkeypatch, [*old, ("snapshot_page", {"title": "Hello"}, "ok", None)])
    page = client.get("/d/x.example").text
    assert 'src="/evidence/1"' in page and "pic empty" not in page


def test_brand_refs_retry_on_www_and_raise_limits_for_official_sites(settings, tmp_path):
    seen = []

    async def grab(url, s, out, max_bytes, max_requests):
        seen.append((url, max_requests))
        ok = url.startswith("https://www.")
        return snapshot.SnapshotResult(
            "ok" if ok else "error",
            None if ok else "ERR_CERT_COMMON_NAME_INVALID",
            url,
            [],
            "t",
            "",
            [],
            None,
            None,
            0,
            {"page": None, "logo": "0f0f0f0f0f0f0f0f", "favicon": None},
        )

    data = asyncio.run(build_brand_refs.build(settings, {"aramex"}, tmp_path / "r.json", grab))
    assert seen == [("https://aramex.com/", 800), ("https://www.aramex.com/", 800)]
    assert data["brands"]["aramex"][0]["logo"] == "0f0f0f0f0f0f0f0f" and not data["failed"]


def test_a_logo_shared_by_two_brands_is_a_common_icon_not_a_logo():
    brands = {
        "a": [{"domain": "a.ae", "logo": "0f0f0f0f0f0f0f0f"}],
        "b": [{"domain": "b.ae", "logo": "0f0f0f0f0f0f0f0e"}],
        "c": [{"domain": "c.ae", "logo": "f0f0f0f0f0f0f0f0"}],
    }
    assert build_brand_refs.drop_shared_logos(brands, 8) == ["a:a.ae", "b:b.ae"]
    assert brands["c"][0]["logo"] == "f0f0f0f0f0f0f0f0" and brands["a"][0]["logo"] is None


@pytest.mark.parametrize(
    ("text", "brand"),
    [
        ("Sewa mobil Solo murah, harga terbaik", None),  # Indonesian "car rent"
        ("Pay your SEWA bill now - Sharjah", "sewa"),
        ("Sharjah Electricity, Water and Gas Authority (SEWA) bill", "sewa"),
        ("Darb toll account top-up in Abu Dhabi", "darb"),
        ("Darb al-Hikma bookshop", None),
        (
            "Sewa mobil Solo murah, harga terbaik. " + "x " * 100 + "Prices also in AED",
            None,
        ),  # a UAE word far away is not context
    ],
)
def test_ordinary_words_name_a_brand_only_next_to_a_uae_word(text, brand):
    s = config.load()
    shown = snapshot.brand_shown("", text, {}, "x.example", s.brands, {}, s.scoring["snapshot"])
    assert (shown or {}).get("brand") == brand


def test_brand_refs_keep_a_good_reference_when_the_official_site_fails_this_time(settings, tmp_path):
    out = tmp_path / "r.json"
    out.write_text(
        json.dumps(
            {"brands": {"dm": [{"domain": "dm.gov.ae", "page": None, "logo": "0f0f0f0f0f0f0f0f", "favicon": None}]}}
        )
    )

    async def grab(url, s, out, max_bytes, max_requests):
        return snapshot.SnapshotResult("timeout", "page did not load", None, [], None, "", [], None, None, 0)

    data = asyncio.run(build_brand_refs.build(settings, {"dm"}, out, grab))
    assert data["brands"]["dm"][0]["logo"] == "0f0f0f0f0f0f0f0f" and "dm.gov.ae" in data["failed"]


def test_parked_brand_domain_drops_to_gray_low_but_a_form_keeps_it_up(settings):
    look = (
        "lookalike",
        {
            "brand": "etisalat",
            "keyword": "etisalat",
            "label": "etisalat-gro8p",
            "score": 1.0,
            "method": "token",
            "position": "registrable",
            "restricted_zone": False,
            "context": "none",
            "context_words": [],
            "mode": "ct",
        },
    )
    gray = assess("etisalat-gro8p.ph", _facts(*_plain(), look), [], None, [], settings.brands, settings.scoring)
    assert gray.components["band"] == "GRAY"
    parked = assess(
        "etisalat-gro8p.ph",
        _facts(*_plain(), look, ("snapshot_page", {"title": "Redirecting...", "parked": "parklogic.com"})),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    assert parked.components["band"] == "GRAY_LOW" and "Parked" in parked.components["reason"]
    form = assess(
        "etisalat-gro8p.ph",
        _facts(
            *_plain(),
            look,
            ("snapshot_page", {"parked": "parklogic"}),
            ("snapshot_form", {"fields": [], "asks": ["card"]}),
        ),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    assert form.components["band"] != "GRAY_LOW"


def test_unsnapshotted_name_on_a_parking_ip_drops_to_gray_low_until_its_own_snapshot(settings):
    look = (
        "lookalike",
        {
            "brand": "etisalat",
            "keyword": "etisalat",
            "label": "etisalat-gro8p",
            "score": 1.0,
            "method": "token",
            "position": "registrable",
            "restricted_zone": False,
            "context": "none",
            "context_words": [],
            "mode": "ct",
        },
    )
    need = settings.scoring["snapshot"]["parked_peers_min"]
    few = assess(
        "etisalat-gro8p.ph",
        _facts(*_plain(), look),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
        parked_peers=need - 1,
    )
    assert few.components["band"] == "GRAY"
    farm = assess(
        "etisalat-gro8p.ph", _facts(*_plain(), look), [], None, [], settings.brands, settings.scoring, parked_peers=need
    )
    assert farm.components["band"] == "GRAY_LOW" and "parked domains" in farm.components["reason"]
    own = assess(
        "etisalat-gro8p.ph",
        _facts(
            *_plain(),
            look,
            ("snapshot_page", {"title": "Etisalat pay"}),
            ("snapshot_form", {"fields": [], "asks": ["card"]}),
        ),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
        parked_peers=need,
    )
    assert own.components["band"] != "GRAY_LOW"  # its own snapshot shows a card form: the neighbours do not matter
    listed = assess(
        "etisalat-gro8p.ph",
        _facts(*_plain(), look, ("in_feed", {"listed": True, "feeds": ["openphish"]})),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
        parked_peers=need,
    )
    assert listed.components["band"] != "GRAY_LOW"  # a phishing list outweighs its parked neighbours


def test_broken_https_is_retried_over_http(settings, tmp_path, monkeypatch):
    urls = []

    async def runner(job, kill_s):
        urls.append(job["url"])
        if job["url"].startswith("https://"):
            return snapshot.SnapshotResult(
                "error",
                "Page.goto: net::ERR_SSL_PROTOCOL_ERROR at https://s3wa.top/",
                None,
                [],
                None,
                "",
                [],
                None,
                None,
                0,
            )
        return snapshot.SnapshotResult("ok", None, job["url"], [], "t", "", [], None, None, 0)

    async def ok(url):
        return netsafe.NormalizedURL(url, url, "https", "s3wa.top", 443, "s3wa.top", "s3wa.top", [])

    monkeypatch.setattr(snapshot, "_run_runner", runner)
    result = asyncio.run(snapshot.capture("https://s3wa.top/", settings, tmp_path / "o", ok))
    assert urls == ["https://s3wa.top/", "http://s3wa.top/"] and result.status == "ok"


def test_a_later_failed_snapshot_cancels_an_old_parked_mark(settings):
    look = (
        "lookalike",
        {
            "brand": "etisalat",
            "keyword": "etisalat",
            "label": "etisalat-gro8p",
            "score": 1.0,
            "method": "token",
            "position": "registrable",
            "restricted_zone": False,
            "context": "none",
            "context_words": [],
            "mode": "ct",
        },
    )
    later = assess(
        "etisalat-gro8p.ph",
        _facts(
            *_plain(),
            look,
            ("snapshot_page", {"parked": "parklogic.com"}),
            ("snapshot_blocked", {"reason": "too many requests"}),
        ),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    assert later.components["band"] == "GRAY"


def test_request_to_an_exfil_channel_is_recorded_and_never_delivered(settings, server, tmp_path):
    site.HITS.clear()
    result = _grab(settings, server, "phish.test", "/exfil", tmp_path)
    assert result.status == "ok" and result.exfil == ["api.telegram.org"] and result.hotlinks == []
    assert "api.telegram.org" not in site.HITS and "phish.test" in site.HITS


def test_files_loaded_from_an_official_brand_domain_are_recorded(settings, server, tmp_path):
    result = _grab(settings, server, "phish.test", "/hotlink", tmp_path)
    assert result.status == "ok" and result.hotlinks == ["rta.ae"] and result.exfil == []
    assert _grab(settings, server, "rta.ae", "/official", tmp_path).hotlinks == []  # the official site loading itself


def test_ordinary_page_has_no_exfil_and_no_hotlinks(settings, server, tmp_path):
    result = _grab(settings, server, "shop.test", "/shop", tmp_path)
    assert result.exfil == [] and result.hotlinks == []


def test_exfil_channel_and_hotlink_add_points_and_reasons(settings):
    shown = ("snapshot_brand", {"brand": "rta", "via": ["name"]})  # a hotlink counts only next to other brand evidence
    base = assess(
        "x.example",
        _facts(*_plain(), shown, ("snapshot_page", {"title": "t"})),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    page = {"title": "t", "exfil": ["api.telegram.org"], "hotlinks": ["rta.ae"]}
    got = assess(
        "x.example", _facts(*_plain(), shown, ("snapshot_page", page)), [], None, [], settings.brands, settings.scoring
    )
    cfg = settings.scoring["snapshot"]
    assert (
        got.components["R"] - base.components["R"] == cfg["exfil_channel"]
        and got.components["B"] - base.components["B"] == cfg["hotlink_official"]
    )
    text = " ".join(got.components["breakdown"])
    assert "page contacts api.telegram.org" in text and "page loads files from rta.ae (official site)" in text


def test_case_shows_exfil_and_hotlink_text(tmp_path, monkeypatch):
    page = {"title": "Hello", "exfil": ["api.telegram.org"], "hotlinks": ["rta.ae"]}
    got = _case_client(tmp_path, monkeypatch, [("snapshot_page", page, "ok", None)]).get("/d/x.example").text
    assert "page contacts api.telegram.org — a channel kits use to send stolen data" in got
    assert "page loads files from rta.ae (official site) — a copied page" in got


@pytest.mark.parametrize("path", ["/exfilv10", "/exfildot", "/exfilwss"])
def test_other_exfil_forms_are_recorded_and_refused(settings, server, tmp_path, path):
    site.HITS.clear()
    result = _grab(settings, server, "phish.test", path, tmp_path)
    expected = {"/exfilv10": "discord.com", "/exfildot": "api.telegram.org", "/exfilwss": "hooks.slack.com"}[path]
    assert result.status == "ok" and result.exfil == [expected]
    assert expected not in site.HITS


def test_redirect_to_the_official_site_is_not_a_hotlink(settings, server, tmp_path):
    result = _grab(settings, server, "shop.test", "/goofficial", tmp_path)
    assert result.status == "ok" and result.final_url.startswith("http://rta.ae") and result.hotlinks == []


def test_exfil_seen_before_a_stop_is_kept_on_the_stored_fact(settings, server, tmp_path):
    result = _grab(settings, server, "phish.test", "/exfilblocked", tmp_path)
    assert result.status == "blocked" and result.exfil == ["api.telegram.org"]
    asyncio.run(intake.submit("phish.test", "manual", [], 0))
    asyncio.run(
        db.run(
            lambda c: snapshot._store(
                c,
                c.execute("SELECT id FROM domains WHERE fqdn = 'phish.test'").fetchone()[0],
                "phish.test",
                result,
                settings,
                15,
            )
        )
    )
    value = asyncio.run(
        db.run(
            lambda c: json.loads(
                c.execute("SELECT value_json FROM facts WHERE type = 'snapshot_blocked'").fetchone()[0]
            )
        )
    )
    assert value["exfil"] == ["api.telegram.org"]
    failed = snapshot.SnapshotResult(
        "timeout", "page did not load", None, [], None, "", [], None, None, 0, exfil=["api.telegram.org"]
    )
    asyncio.run(
        db.run(
            lambda c: snapshot._store(
                c,
                c.execute("SELECT id FROM domains WHERE fqdn = 'phish.test'").fetchone()[0],
                "phish.test",
                failed,
                settings,
                15,
            )
        )
    )
    row = asyncio.run(
        db.run(
            lambda c: c.execute(
                "SELECT value_json, status FROM facts WHERE type = 'snapshot_page' ORDER BY id DESC"
            ).fetchone()
        )
    )
    assert row["status"] == "error" and json.loads(row["value_json"])["exfil"] == ["api.telegram.org"]


def test_hotlink_alone_is_no_brand_evidence_and_never_lifts_a_domain(settings):
    plain = [*_plain(), ("snapshot_page", {"title": "t"})]
    base = assess("old-shop.example", _facts(*plain), [], None, [], settings.brands, settings.scoring)
    hot = assess(
        "old-shop.example",
        _facts(*_plain(), ("snapshot_page", {"title": "t", "hotlinks": ["rta.ae"]})),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    assert (
        hot.components["B"] == base.components["B"] == 0
        and hot.components["band"] == base.components["band"] != "FURTHER"
    )


def test_hotlink_next_to_a_lookalike_adds_points_but_does_not_leave_noise(settings):
    look = (
        "lookalike",
        {
            "brand": "rta",
            "keyword": "rta",
            "label": "rta-pay",
            "score": 1.0,
            "method": "token",
            "position": "registrable",
            "restricted_zone": False,
            "context": "none",
            "context_words": [],
            "mode": "ct",
        },
    )
    base = assess(
        "rta-pay.example",
        _facts(*_plain(), look, ("snapshot_page", {"title": "t"})),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    hot = assess(
        "rta-pay.example",
        _facts(*_plain(), look, ("snapshot_page", {"title": "t", "hotlinks": ["rta.ae"]})),
        [],
        None,
        [],
        settings.brands,
        settings.scoring,
    )
    assert hot.components["B"] - base.components["B"] == settings.scoring["snapshot"]["hotlink_official"]
    assert (hot.components["band"] == "NOISE") == (base.components["band"] == "NOISE")


def _queue(names, generic=()):
    """Queued GRAY_LOW domains that resolve, listed oldest first; names in `generic` carry a generic_name lookalike."""

    def prep(conn):
        for i, name in enumerate(names):
            did = conn.execute(
                "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state) VALUES (?, ?, ?, 'ct_tiled', 'REVIEW')",
                (name, name, f"2026-11-20T10:{i:02d}:00Z"),
            ).lastrowid
            conn.execute(
                "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) VALUES (?, 'v', 0.1, 1, 'REVIEW', '[\"GRAY_LOW\"]', '{}', '[]', '2026-11-20T00:00:00Z')",
                (did,),
            )
            conn.execute(
                "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, 'dns_a', '{}', 'dns', '2026-11-20T00:00:00Z', 'ok')",
                (did,),
            )
            conn.execute(
                "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, 'lookalike', ?, 'ct_tiled', '2026-11-20T00:00:00Z', 'ok')",
                (did, json.dumps({"method": "generic_name" if name in generic else "smishing_pattern"})),
            )
        conn.commit()

    asyncio.run(db.run(prep))


def _run_monitor(settings, monkeypatch, seconds=0.6):
    """Run monitor_snapshots against a fake take that records overlap; returns (started order, max at once)."""
    from scamshield import app

    started, state = [], {"now": 0, "max": 0}

    async def fake_take(s, fqdn, auto=False, **_):
        started.append(fqdn)
        state["now"] += 1
        state["max"] = max(state["max"], state["now"])
        await asyncio.sleep(0.1)
        state["now"] -= 1
        await db.run(
            lambda c: (
                c.execute(
                    "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES ((SELECT id FROM domains WHERE fqdn = ?), 'snapshot_page', '{}', 'snapshot', 'x', 'ok')",
                    (fqdn,),
                ),
                c.commit(),
            )
        )

    monkeypatch.setattr(snapshot, "take", fake_take)

    async def go():
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(app.monitor_snapshots(settings), seconds)

    asyncio.run(go())
    return started, state["max"]


def test_parallel_snapshots_take_different_domains_up_to_the_limit(settings, monkeypatch):
    settings.sources["snapshot"].extra.update(concurrency=3, auto_every_s=0.05)
    settings.sources["snapshot"].budget_per_hour = 120
    names = [f"d{i}.example" for i in range(7)]
    _queue(names)
    started, peak = _run_monitor(settings, monkeypatch)
    assert sorted(started) == sorted(names)  # all seven, none twice, even while another one is running
    assert peak == 3


def test_hourly_budget_holds_with_parallel_snapshots(settings, monkeypatch):
    settings.sources["snapshot"].extra.update(concurrency=3, auto_every_s=0.05)
    settings.sources["snapshot"].budget_per_hour = 4
    _queue([f"d{i}.example" for i in range(9)])
    started, _ = _run_monitor(settings, monkeypatch)
    assert len(started) == 4


def test_brand_domains_are_claimed_before_generic_ones(settings):
    _queue(["old-brand.example", "new-generic.example", "new-brand.example"], generic={"new-generic.example"})
    snapshot._claims["n"] = 0
    running: set[str] = set()
    order = [asyncio.run(snapshot.claim_auto(settings, running)) for _ in range(3)]
    assert (
        order == ["new-brand.example", "old-brand.example", "new-generic.example"]
        and asyncio.run(snapshot.claim_auto(settings, running)) is None
    )


def test_manual_snapshot_does_not_wait_for_automatic_ones(settings, monkeypatch):
    from types import SimpleNamespace

    gate, entered = {}, []

    async def runner(job, kill_s):
        entered.append(job["url"])
        if "auto" in job["url"]:
            await gate["release"].wait()
        return snapshot.SnapshotResult("timeout", "x", None, [], None, "", [], None, None, 0)

    async def accept(url):
        return SimpleNamespace(url=url)

    async def go():
        gate["release"] = asyncio.Event()
        autos = [
            asyncio.create_task(
                snapshot.capture(
                    f"https://auto{i}.example/", settings, Path(settings.evidence_dir) / str(i), accept, auto=True
                )
            )
            for i in range(3)
        ]
        await asyncio.sleep(0.05)
        manual = await asyncio.wait_for(
            snapshot.capture("https://manual.example/", settings, Path(settings.evidence_dir) / "m", accept), 2
        )  # the automatic three are still running
        gate["release"].set()
        await asyncio.gather(*autos)
        return manual

    monkeypatch.setattr(snapshot, "_run_runner", runner)
    assert asyncio.run(go()).status == "timeout" and len(entered) == 4


def test_every_third_automatic_snapshot_goes_to_a_brandless_name(settings):
    _queue(["b1.example", "b2.example", "b3.example", "b4.example", "gen.example"], generic={"gen.example"})
    snapshot._claims["n"] = 0
    running: set[str] = set()
    order = [asyncio.run(snapshot.claim_auto(settings, running)) for _ in range(3)]
    assert (
        order[2] == "gen.example" and "gen.example" not in order[:2]
    )  # brands still left, yet the brandless one gets its turn


def test_godaddy_for_sale_redirect_is_parked():
    """talabat.xyz: redirect to forsale.godaddy.com answered "Access Denied" — no parking text, but the for-sale host is the marker."""
    from scamshield.snapshot_runner import parked_marker

    assert (
        parked_marker("forsale.godaddy.com", {"talabat.xyz", "forsale.godaddy.com"}, "Access Denied")
        == "forsale.godaddy.com"
    )
    assert parked_marker("www.godaddy.com", {"www.godaddy.com"}, "") is None  # GoDaddy's own site is not a parked page
