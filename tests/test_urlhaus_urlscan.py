import asyncio
import dataclasses
import json
from pathlib import Path

import httpx
import pytest

from scamshield import config, db, runtime
from scamshield.connectors import urlhaus, urlscan
from scamshield.web import routes

FIX = Path(__file__).parent / "fixtures" / "sources"
NOW = "2026-11-20T16:00:00Z"


class _Http:
    """Recorded answer for every GET; `calls` keeps (url, headers)."""

    def __init__(self, body, status=200):
        self.body, self.status, self.calls = body, status, []

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs.get("headers")))
        return httpx.Response(self.status, json=self.body)


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    for name in ("ABUSECH_AUTH_KEY", "URLSCAN_API_KEY"):
        monkeypatch.setenv(name, "test-key")
    settings = config.load()
    db.init(settings.db_path)
    return settings


def _ctx(settings, http):
    return dataclasses.replace(runtime.make_ctx(settings, http, "auto"), now=lambda: NOW)


def _load(name):
    return json.loads((FIX / name).read_text())


def _query(settings, sql, *args):
    import sqlite3

    return sqlite3.connect(settings.db_path).execute(sql, args).fetchall()


def test_urlhaus_path_only_brand_is_queued_with_fact_and_benign_never(settings):
    http = _Http(_load("urlhaus_recent.json"))
    result = asyncio.run(urlhaus.run_once(_ctx(settings, http)))

    assert result == {"candidates": 1, "error": None}
    assert http.calls[0][1] == {"Auth-Key": "test-key"}
    assert _query(settings, "SELECT fqdn, found_by FROM domains") == [
        ("dwu6.top", "urlhaus")
    ]  # official, github, bare IP, offline, no brand: none
    fact = _query(settings, "SELECT value_json, source, observed_at FROM facts WHERE type = 'urlhaus_listed'")
    assert json.loads(fact[0][0]) == {
        "url": "http://dwu6.top/rta/pay/index.php",
        "threat": "malware_download",
        "tags": ["phishing", "apk"],
        "date_added": "2026-11-20T14:03:05Z",
        "reference": "https://urlhaus.abuse.ch/url/1/",
    }
    assert fact[0][1:] == ("urlhaus", "2026-11-20T14:03:05Z")
    assert json.loads(_query(settings, "SELECT value_json FROM facts WHERE type = 'lookalike'")[0][0])["brand"] == "rta"
    assert _query(settings, "SELECT url FROM urls") == [("http://dwu6.top/rta/pay/index.php",)]


def test_no_key_shows_off_and_makes_no_request(settings, monkeypatch):
    monkeypatch.delenv("ABUSECH_AUTH_KEY")
    monkeypatch.delenv("URLSCAN_API_KEY")
    settings = config.load()
    http = _Http(_load("urlhaus_recent.json"))
    asyncio.run(urlhaus.run_once(_ctx(settings, http)))
    asyncio.run(urlscan.run_once(_ctx(settings, http)))

    assert http.calls == []
    rows = {
        r[0]: {"name": r[0], "status": r[1], "last_success_at": r[2], "last_error": r[3]}
        for r in _query(settings, "SELECT name, status, last_success_at, last_error FROM sources")
    }
    assert routes._pull_source(rows, "urlhaus", "URLhaus")["status"] == "off — no key"
    assert routes._pull_source(rows, "urlscan", "urlscan")["state"] == "grey"


def test_urlhaus_failure_is_data_and_shows_amber(settings):
    result = asyncio.run(urlhaus.run_once(_ctx(settings, _Http({}, 401))))

    assert result["error"] == "http_401"
    row = _query(settings, "SELECT name, status, last_success_at, last_error FROM sources")[0]
    shown = routes._pull_source(
        {"urlhaus": dict(zip(("name", "status", "last_success_at", "last_error"), row, strict=True))},
        "urlhaus",
        "URLhaus",
    )
    assert shown["state"] == "amber" and "http_401" in shown["status"]


def test_urlscan_queues_only_non_official_page_facts(settings):
    http = _Http(_load("urlscan_search.json"))
    result = asyncio.run(urlscan.run_once(_ctx(settings, http)))

    assert result["error"] is None and result["queries"] == len(http.calls)
    assert http.calls[0][1] == {"api-key": "test-key"}
    assert "page.title" in http.calls[0][0] and "urlscan.io/api/v1/search/" in http.calls[0][0]
    assert {r[0] for r in _query(settings, "SELECT fqdn FROM domains")} == {
        "rta-fines.example-scam.top"
    }  # official, wikipedia, IP, news page titled "RTA ..." skipped
    facts = _query(
        settings, "SELECT value_json, source, observed_at FROM facts WHERE domain_id IN (SELECT id FROM domains)"
    )
    value = json.loads(facts[0][0])
    assert value["title"] == "Roads and Transport Authority - Pay fines" and value["match"] == "title"
    assert value["result_url"] == "https://urlscan.io/result/01a1f97a-ffe1-7258-bd3d-5b783cb49de0/"
    assert "verdicts" not in value and "malicious" not in facts[0][0]
    assert facts[0][1:] == ("urlscan", "2026-11-20T15:02:50.216Z")


def test_urlscan_stops_at_daily_budget(settings):
    cfg = settings.sources["urlscan"]
    settings.sources["urlscan"] = dataclasses.replace(cfg, budget_per_day=2)
    http = _Http({"results": []})
    result = asyncio.run(urlscan.run_once(_ctx(settings, http)))

    assert len(http.calls) == 2 and result == {"queries": 2, "candidates": 0, "error": "budget"}


def test_urlscan_adds_one_favicon_query_per_brand_from_brand_refs():
    refs = {
        "dubaicustoms": [
            {"domain": "dubaicustoms.gov.ae", "favicon": "b" * 64},
            {"domain": "x.ae", "favicon": "a" * 64},
            {"domain": "y.ae", "favicon": None},
        ],
        "rta": [{"domain": "rta.ae", "favicon": None}],
    }
    cfg = {"queries": {"rta": {"title": ["Roads and Transport Authority"]}}, "favicons_from_refs": True}
    assert urlscan._queries(cfg, refs) == [
        ("rta", "title", 'page.title:"Roads and Transport Authority"'),
        ("dubaicustoms", "favicon", f'hash:("{"a" * 64}" OR "{"b" * 64}")'),
    ]
    assert urlscan._queries({**cfg, "favicons_from_refs": False}, refs) == [
        ("rta", "title", 'page.title:"Roads and Transport Authority"')
    ]


def test_a_favicon_hit_is_queued_even_when_the_name_has_no_brand_in_it(settings):
    """dubai.aeizt.top (March 2026) carried the Dubai Customs favicon: the name alone says nothing."""
    item = {
        "page": {
            "domain": "dubai.aeizt.top",
            "url": "https://dubai.aeizt.top/",
            "title": "Customs Information Customs Notices",
        },
        "task": {"uuid": "u-1", "time": "2026-03-25T10:00:00Z"},
    }
    queued = []

    async def submit(host, found_by, facts, priority):
        queued.append((host, facts[0].value["match"]))

    import scamshield.intake as intake_mod

    original, intake_mod.submit = intake_mod.submit, submit
    try:
        n = asyncio.run(
            urlscan._submit(_ctx(settings, None), "dubaicustoms", "favicon", [item], "2026-11-21T10:00:00Z")
        )
    finally:
        intake_mod.submit = original
    assert n == 1 and queued[0] == ("dubai.aeizt.top", "favicon")


def test_many_scans_of_one_host_give_one_fact_from_the_newest_scan(settings):
    scans = [
        {
            "page": {"domain": "otcsniperalgo.net", "url": "https://otcsniperalgo.net/"},
            "task": {"uuid": f"u-{i}", "time": f"2026-11-1{i}T10:00:00Z"},
        }
        for i in range(5)
    ]
    queued = []

    async def submit(host, found_by, facts, priority):
        queued.append((host, facts[0].value["scan_date"]))

    import scamshield.intake as intake_mod

    original, intake_mod.submit = intake_mod.submit, submit
    try:
        n = asyncio.run(urlscan._submit(_ctx(settings, None), "citiae", "favicon", scans, "2026-11-21T10:00:00Z"))
    finally:
        intake_mod.submit = original
    assert n == 1 and queued == [("otcsniperalgo.net", "2026-11-14T10:00:00Z")]
