"""Find relatives (idea 4): signals from the case's urlscan scan, at most 3 urlscan searches per click, a separate daily budget,
found domains only queued (never marked scam), links stored as facts the graph turns into edges. Recorded-format answers only, no network."""

import asyncio
import dataclasses
import json
import sqlite3
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from scamshield import config, db, graph, runtime
from scamshield.connectors import urlscan_relatives

FIX = Path(__file__).parent / "fixtures" / "sources" / "relatives"
NOW = "2026-11-21T12:00:00Z"
ORIGIN = "dubai-customs-pay.top"
SCAN = "https://urlscan.io/result/0a0a0a0a-1111-4222-8333-444455556666/"


def _load(name):
    return json.loads((FIX / name).read_text())


class _Http:
    """Answers like urlscan: the result API by uuid, the search API by the hash / IP in q. `calls` keeps the decoded queries."""

    def __init__(self, status=200, boom=None, result=None, answers=None):
        self.status, self.boom, self.calls, self.result, self.answers = status, boom, [], result, answers or {}

    async def get(self, url, **kwargs):
        if self.boom:
            raise self.boom
        parts = urlsplit(url)
        q = parse_qs(parts.query).get("q", [""])[0]
        self.calls.append(q or parts.path)
        if self.status != 200:
            return httpx.Response(self.status, json={"message": "error"})
        if "/result/" in parts.path:
            return httpx.Response(200, json=self.result or _load("result_origin.json"))
        for needle, body in self.answers.items():
            if needle in q:
                return httpx.Response(200, json=body)
        if q.startswith("page.domain:"):
            return httpx.Response(200, json=_load("search_lookup.json"))
        if '"' + "a" * 64 in q:
            return httpx.Response(200, json=_load("search_common.json"))
        if '"' + "b" * 64 in q:
            return httpx.Response(200, json=_load("search_mainjs.json"))
        return httpx.Response(200, json={"total": 0, "results": []})


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
    settings = config.load()
    db.init(settings.db_path)
    return settings


def _origin(path, with_scan=True):
    conn = sqlite3.connect(path)
    conn.execute(
        f"INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score) VALUES ('{ORIGIN}', '{ORIGIN}', '2026-11-20T08:00:00Z', 'urlscan', 'REVIEW', 0.6)"
    )
    if with_scan:
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status) VALUES (1, 'urlscan_hit', ?, 'urlscan', '2026-11-20T10:00:00Z', '2026-11-20T11:00:00Z', 'ok')",
            (
                json.dumps(
                    {
                        "brand": "dubaicustoms",
                        "match": "favicon",
                        "title": "Dubai Customs",
                        "scan_date": "2026-11-20T10:00:00.000Z",
                        "result_url": SCAN,
                    }
                ),
            ),
        )
    conn.commit()
    conn.close()


def _run(settings, http, fqdn=ORIGIN):
    ctx = dataclasses.replace(runtime.make_ctx(settings, http, "manual"), now=lambda: NOW)
    return asyncio.run(urlscan_relatives.find(ctx, fqdn))


def _q(settings, sql, *args):
    return sqlite3.connect(settings.db_path).execute(sql, args).fetchall()


def test_relatives_are_queued_with_reason_and_nothing_is_marked_scam(settings):
    _origin(settings.db_path)
    http = _Http()
    result = _run(settings, http)

    # at most 3 urlscan requests per click, the read of the case's own scan included: then the first-party scripts in page order
    assert http.calls[0].startswith("/api/v1/result/0a0a0a0a")
    assert http.calls[1:] == [f'hash:"{"a" * 64}"', f'hash:"{"b" * 64}"']
    assert result["queued"] == ["customs-ae-fee.top", "k7qz2.xyz"] and result["error"] is None
    found = dict(_q(settings, "SELECT fqdn, found_by FROM domains WHERE fqdn != ?", ORIGIN))
    assert found == {
        "customs-ae-fee.top": "relatives",
        "k7qz2.xyz": "relatives",
    }  # not the official site, not itself, not the common-library hit
    value, source, observed, fetched = _q(
        settings,
        "SELECT f.value_json, f.source, f.observed_at, f.fetched_at FROM facts f JOIN domains d ON d.id = f.domain_id "
        "WHERE d.fqdn = 'customs-ae-fee.top' AND f.type = 'relative_link'",
    )[0]
    value = json.loads(value)
    assert value["reason"] == f"found via relative: same main.js as {ORIGIN}"
    assert value["feature"] == "script" and value["value"] == "b" * 64 and value["origin"] == ORIGIN
    assert value["scan_date"] == "2026-11-19T08:15:00.000Z" and value["result_url"].endswith(
        "b1000000-0000-4000-8000-000000000001/"
    )
    assert (source, observed, fetched) == ("urlscan", "2026-11-19T08:15:00.000Z", NOW)
    # only queued for a check: no verdict, no state, and the case itself is not re-queued
    assert _q(settings, "SELECT count(*) FROM feedback") == [(0,)]
    assert _q(settings, "SELECT state FROM domains WHERE fqdn != ?", ORIGIN) == [(None,), (None,)]
    assert sorted(r[0] for r in _q(settings, "SELECT target FROM jobs WHERE kind = 'check_domain'")) == [
        "customs-ae-fee.top",
        "k7qz2.xyz",
    ]


def test_common_library_is_skipped_and_said_so(settings):
    _origin(settings.db_path)
    result = _run(settings, _Http())
    assert any("jquery.min.js" in s and "812" in s for s in result["skipped"])
    assert _q(settings, "SELECT count(*) FROM domains WHERE fqdn = 'some-shop.com'") == [(0,)]
    run = json.loads(_q(settings, "SELECT value_json FROM facts WHERE type = 'relatives_run'")[-1][0])
    assert "2 sites queued" in run["message"] and "common library" in run["message"]


def test_daily_budget_stops_the_search(settings):
    _origin(settings.db_path)
    settings.sources["urlscan_relatives"] = dataclasses.replace(settings.sources["urlscan_relatives"], budget_per_day=2)
    http = _Http()
    result = _run(settings, http)
    assert len(http.calls) == 2  # the scan read + one search; the 3rd request is refused before it is sent
    assert result["error"] == "budget" and result["queued"] == []
    assert "daily limit" in result["message"].lower()
    assert _q(settings, "SELECT count(*) FROM domains") == [(1,)]


def test_budget_is_separate_from_the_brand_search(settings):
    assert settings.sources["urlscan_relatives"].budget_per_day == 30
    assert settings.sources["urlscan_relatives"].extra["max_queries_per_click"] == 3
    assert settings.sources["urlscan_relatives"].extra["popular_max"] == 50


def test_without_a_stored_scan_the_lookup_counts_toward_the_three_searches(settings):
    _origin(settings.db_path, with_scan=False)
    http = _Http()
    _run(settings, http)
    assert (
        http.calls[0] == f'page.domain:"{ORIGIN}"'
        and http.calls[1].startswith("/api/v1/result/")
        and len(http.calls) == 3
    )


def test_edges_carry_the_evidence_and_the_scan_date(settings):
    _origin(settings.db_path)
    _run(settings, _Http())
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    edges = graph.card_view(conn, ORIGIN, settings.scoring, settings.shared_infra)
    pairs = {(e["a"], e["b"]): e for e in edges}
    assert set(pairs) == {("customs-ae-fee.top", ORIGIN), (ORIGIN, "k7qz2.xyz"), ("customs-ae-fee.top", "k7qz2.xyz")}
    edge = pairs["customs-ae-fee.top", ORIGIN]
    assert edge["level"] == "strong" and edge["title"] == "same main.js, urlscan scan of 2026-11-19 (strong)"
    assert "urlscan scan of 2026-11-19" in edge["sentence"]
    assert {ev["source"] for ev in edge["evidence"]} == {"urlscan"} and all(
        ev["fetched_at"] == NOW for ev in edge["evidence"]
    )


def test_urlscan_error_is_data_never_an_exception(settings):
    _origin(settings.db_path)
    for http in (_Http(status=500), _Http(status=429), _Http(boom=RuntimeError("socket exploded"))):
        result = _run(settings, http)
        assert result["error"] and "urlscan unavailable" in result["message"]


def _client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("URLSCAN_API_KEY", "test-key")
    client = TestClient(create_app(background=False))
    client.__enter__()
    _origin(tmp_path / "scamshield.db")
    return client


def test_card_has_the_button_and_shows_a_friendly_message_when_urlscan_fails(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    page = client.get(f"/d/{ORIGIN}").text
    assert f'action="/d/{ORIGIN}/relatives"' in page and "Find relatives" in page
    client.app.state.http = _Http(boom=RuntimeError("socket exploded"))
    got = client.post(f"/d/{ORIGIN}/relatives")
    assert got.status_code == 200 and "urlscan unavailable" in got.text
    client.app.state.http = _Http(status=503)
    got = client.post(f"/d/{ORIGIN}/relatives")
    assert got.status_code == 200 and "urlscan unavailable right now (source error)" in got.text


def test_card_shows_the_found_relatives_in_the_links_graph(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    client.app.state.http = _Http()
    page = client.post(f"/d/{ORIGIN}/relatives").text
    assert "2 sites queued" in page
    assert "same main.js, urlscan scan of 2026-11-19" in page and "k7qz2.xyz" in page
    assert "found via a relative of another case" in client.get("/d/k7qz2.xyz").text


# ---------- review / live-check fixes ----------

GANG_SHA = "1a27e992576f8aaf2c1f177c580622923d3d3a9264f43740bb1f4fb8676a7c5d"
GANG = "dubai.customsnid.top"


def _gang_scan():
    """The Dubai Customs fake seen in a live check: Cloudflare's own email-decode script on the site host, the kit main.js."""

    def req(kind, url, sha):
        return {
            "request": {"type": kind, "request": {"url": url, "method": "GET"}},
            "response": {"hash": sha, "response": {"url": url}},
        }

    return {
        "task": {"uuid": "019d89f4-d64b-76eb-8801-939b14c77830", "time": "2026-04-14T12:00:00.000Z", "domain": GANG},
        "page": {"domain": GANG, "url": f"https://{GANG}/", "ip": "104.21.4.147", "asn": "AS13335"},
        "data": {
            "requests": [
                req("Document", f"https://{GANG}/", "1" * 64),
                req(
                    "Script", f"https://{GANG}/cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js", "f" * 64
                ),
                req("Script", f"https://{GANG}/static/js/main.js", GANG_SHA),
            ]
        },
    }


def _insert(path, fqdn, state="REVIEW", scan_uuid=None):
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score) VALUES (?, ?, '2026-11-20T08:00:00Z', 'urlscan', ?, 0.6)",
        (fqdn, fqdn, state),
    )
    if scan_uuid:
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status) SELECT id, 'urlscan_hit', ?, 'urlscan', '2026-11-20T10:00:00Z', "
            "'2026-11-20T11:00:00Z', 'ok' FROM domains WHERE fqdn = ?",
            (json.dumps({"result_url": f"https://urlscan.io/result/{scan_uuid}/"}), fqdn),
        )
    conn.commit()
    conn.close()


def test_gang_main_js_on_46_domains_is_not_a_common_library(settings):
    """A live check: 61 scans of one kit main.js over 46 domains (Salik, Dubai Police, Darb, Customs...). Counting scans skipped it; distinct sites do not."""
    _insert(settings.db_path, GANG, scan_uuid="019d89f4-d64b-76eb-8801-939b14c77830")
    http = _Http(result=_gang_scan(), answers={GANG_SHA: _load("search_gang_mainjs.json")})
    result = _run(settings, http, GANG)
    assert not any("f" * 64 in c for c in http.calls)  # /cdn-cgi/ is Cloudflare's, never a search
    assert http.calls[1] == f'hash:"{GANG_SHA}"' and len(http.calls) == 2  # Cloudflare IP: not rare, not searched
    assert result["skipped"] == [] and result["error"] is None
    assert len(result["queued"]) == 25  # 45 relatives, capped per click (config max_queued_per_click)
    assert "salik.ae.billb.top" in result["queued"] or "bankwest-ac.cc" in result["queued"]
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    edges = graph.card_view(conn, GANG, settings.scoring, settings.shared_infra)
    assert edges and {e["level"] for e in edges if GANG in (e["a"], e["b"])} == {"strong"}


def test_common_is_decided_by_distinct_sites_not_scan_count(settings):
    one_site = {
        "total": 5000,
        "results": [
            {
                "task": {"uuid": f"d0000000-0000-4000-8000-{i:012d}", "time": "2026-11-20T10:00:00.000Z"},
                "page": {"domain": "kit-panel-one.top"},
            }
            for i in range(100)
        ],
    }
    _origin(settings.db_path)
    result = _run(settings, _Http(answers={"b" * 64: one_site}))
    assert result["queued"] == ["kit-panel-one.top"] and not any("main.js" in s for s in result["skipped"])


def test_missing_total_field_still_works(settings):
    _origin(settings.db_path)
    body = _load("search_mainjs.json")
    body.pop("total")
    result = _run(settings, _Http(answers={"b" * 64: body}))
    assert result["queued"] == ["customs-ae-fee.top", "k7qz2.xyz"] and result["error"] is None


def test_attacker_hosts_never_reach_a_query(settings):
    _origin(settings.db_path)
    scan = _load("result_origin.json")
    scan["data"]["requests"] = [
        {"request": {"type": "WebSocket", "request": {"url": 'wss://a" OR domain:"google.com/x'}}, "response": {}},
        {"request": {"type": "WebSocket", "request": {"url": "wss://panel.evil-kit.top/ws"}}, "response": {}},
        {
            "request": {"type": "Script", "request": {"url": "https://dubai-customs-pay.top/x.js"}},
            "response": {"hash": 'abc" OR hash:"x'},
        },
    ]
    found = {
        "total": 1,
        "results": [
            {
                "task": {"uuid": "e0000000-0000-4000-8000-000000000001", "time": "2026-11-20T10:00:00.000Z"},
                "page": {"domain": 'bad" host.top'},
            },
            {
                "task": {"uuid": "e0000000-0000-4000-8000-000000000002", "time": "2026-11-20T10:00:00.000Z"},
                "page": {"domain": "kit-two.top"},
            },
        ],
    }
    http = _Http(result=scan, answers={"panel.evil-kit.top": found})
    result = _run(settings, http)
    assert http.calls[1] == 'domain:"panel.evil-kit.top"'
    assert not any("google.com" in c or "OR" in c for c in http.calls)
    assert result["queued"] == ["kit-two.top"]


def test_long_attacker_file_names_are_clipped(settings):
    _origin(settings.db_path)
    scan = _load("result_origin.json")
    long_name = "x" * 300 + ".js"
    scan["data"]["requests"] = [
        {
            "request": {"type": "Script", "request": {"url": f"https://dubai-customs-pay.top/{long_name}"}},
            "response": {"hash": "b" * 64},
        }
    ]
    _run(settings, _Http(result=scan))
    for (value,) in _q(settings, "SELECT value_json FROM facts WHERE type IN ('relative_link', 'relatives_run')"):
        value = json.loads(value)
        assert len(value.get("file") or "") <= 80 and "x" * 81 not in value.get("reason", "") + value.get("message", "")


def test_third_party_file_gives_at_most_a_medium_link_even_to_a_confirmed_scam(settings):
    signal = {
        s["file"]: s
        for s in urlscan_relatives.signals(_load("result_origin.json"), runtime.make_ctx(settings, None, "manual"))
    }
    assert (
        signal["js"]["feature"] == "script_3p" and signal["main.js"]["feature"] == "script"
    )  # gtag/js from googletagmanager vs the site's own file
    conn = sqlite3.connect(settings.db_path)
    for name in (ORIGIN, "confirmed-scam.top"):
        conn.execute(
            "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by) VALUES (?, ?, '2026-11-20T08:00:00Z', 'relatives')",
            (name, name),
        )
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status) SELECT id, 'relative_link', ?, 'urlscan', ?, ?, 'ok' FROM domains WHERE fqdn = ?",
            (
                json.dumps(
                    {"feature": "script_3p", "value": "d" * 64, "file": "js", "origin": ORIGIN, "scan_date": NOW}
                ),
                NOW,
                NOW,
                name,
            ),
        )
    conn.execute(
        "INSERT INTO feedback (domain_id, verdict, reason, created_at) SELECT id, 'scam', 'test', ? FROM domains WHERE fqdn = 'confirmed-scam.top'",
        (NOW,),
    )
    conn.commit()
    conn.row_factory = sqlite3.Row
    edges = graph.card_view(conn, ORIGIN, settings.scoring, settings.shared_infra)
    assert edges and all(e["level"] != "strong" for e in edges)


def test_known_domains_are_linked_not_requeued_and_queue_is_capped(settings):
    _origin(settings.db_path)
    _insert(settings.db_path, "customs-ae-fee.top")
    settings.sources["urlscan_relatives"].extra["max_queued_per_click"] = 1
    result = _run(settings, _Http())
    assert result["linked"] == ["customs-ae-fee.top"] and result["queued"] == ["k7qz2.xyz"]
    assert _q(settings, "SELECT target FROM jobs WHERE kind = 'check_domain'") == [("k7qz2.xyz",)]
    assert _q(
        settings,
        "SELECT count(*) FROM facts f JOIN domains d ON d.id = f.domain_id WHERE d.fqdn = 'customs-ae-fee.top' AND f.type = 'relative_link'",
    ) == [(1,)]


def test_queue_cap_is_configured(settings):
    assert settings.sources["urlscan_relatives"].extra["max_queued_per_click"] == 25


def test_official_domains_are_refused_server_side(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _insert(
        tmp_path / "scamshield.db",
        "dubaicustoms.gov.ae",
        state="REVIEW",
        scan_uuid="0a0a0a0a-1111-4222-8333-444455556666",
    )
    client.app.state.http = http = _Http()
    page = client.post("/d/dubaicustoms.gov.ae/relatives").text
    assert http.calls == [] and "Official domain" in page


def test_validators_reject_trailing_newline():
    """`$` lets a trailing newline through; fullmatch does not (review 2)."""
    from scamshield.connectors import urlscan_relatives as ur

    assert not ur.valid_host("evil.com\n") and ur.valid_host("evil.com")
    assert not ur._SHA.fullmatch("a" * 64 + "\n") and not ur._UUID.fullmatch(
        "0" * 8 + "-0000-0000-0000-" + "0" * 12 + "\n"
    )
