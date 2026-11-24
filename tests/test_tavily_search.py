import asyncio
import dataclasses
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from scamshield import app as app_module
from scamshield import config, db, runtime
from scamshield.connectors import tavily_search
from scamshield.enrich.lookalike import is_regional_official
from scamshield.web import routes

BODY = json.loads((Path(__file__).parent / "fixtures" / "search" / "tavily_rta.json").read_text())
T0 = datetime(2026, 11, 19, 8, 0, tzinfo=UTC)


def _iso(moment):
    return moment.isoformat().replace("+00:00", "Z")


class _Http:
    """Recorded Tavily answer; `status` overrides the HTTP code, `calls` keeps every request."""

    def __init__(self, status=200, body=BODY):
        self.status, self.body, self.calls = status, body, []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return httpx.Response(self.status, json=self.body if self.status == 200 else {"error": "x"})


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    settings = config.load()
    db.init(settings.db_path)
    return settings


def _ctx(settings, http, moment=T0):
    return dataclasses.replace(runtime.make_ctx(settings, http, "manual"), now=lambda: _iso(moment))


def _domains(conn):
    return {r["fqdn"]: dict(r) for r in conn.execute("SELECT fqdn, found_by, data_mode FROM domains")}


def test_official_domain_marked_not_queued_unofficial_queued(settings):
    http = _Http()
    result = asyncio.run(tavily_search.search(_ctx(settings, http), "pay RTA fine"))

    assert result["status"] == "ok"
    by_host = {r["host"]: r for r in result["results"]}
    assert by_host["www.rta.ae"]["is_official"] is True
    assert by_host["rta-fines-pay.example-scam.com"]["is_official"] is False
    queued = asyncio.run(db.run(_domains))
    assert set(queued) == {"rta-fines-pay.example-scam.com"}  # gulfnews.example.com has no brand in its name
    assert queued["rta-fines-pay.example-scam.com"]["found_by"] == "web search"
    saved = asyncio.run(
        db.run(
            lambda c: [
                tuple(r)
                for r in c.execute("SELECT rank, is_official, domain_id IS NOT NULL FROM search_results ORDER BY rank")
            ]
        )
    )
    assert saved == [
        (1, 1, 0),
        (2, 0, 1),
        (3, 0, 0),
    ]  # same site twice -> one row; the unqueued result is saved without a domain


def test_flood_of_44_results_queues_only_brand_lookalikes_and_saves_all(settings):
    body = json.loads((Path(__file__).parent / "fixtures" / "search" / "tavily_flood.json").read_text())
    assert len(body["results"]) == 44
    asyncio.run(tavily_search.search(_ctx(settings, _Http(body=body)), "pay RTA fine"))

    queued = asyncio.run(db.run(_domains))
    assert set(queued) == {"salik-fine-pay.com", "rta-fines.top"}  # evgfinescheck.com names no brand
    assert not any(h.endswith("gov.ae") or h == "u.ae" for h in queued)
    assert asyncio.run(db.run(lambda c: c.execute("SELECT count(*) FROM search_results").fetchone()[0])) == 44


def test_regional_official_site_is_queued_by_lookalike_but_never_auto_further(settings):
    body = {"results": [{"url": "https://online.adcb.com.eg/login", "title": "ADCB Egypt"}]}
    asyncio.run(tavily_search.search(_ctx(settings, _Http(body=body)), "adcb login"))

    assert set(asyncio.run(db.run(_domains))) == {"online.adcb.com.eg"}
    assert is_regional_official(
        "online.adcb.com.eg", config.load_brands(Path("config/brands.yaml"))
    )  # scoring caps such hosts at GRAY (test_scoring)


def test_keyless_request_shape(settings):
    http = _Http()
    asyncio.run(tavily_search.search(_ctx(settings, http), "pay RTA fine"))

    url, kwargs = http.calls[0]
    assert url == "https://api.tavily.com/search"
    assert kwargs["headers"]["X-Tavily-Access-Mode"] == "keyless"
    assert "Authorization" not in kwargs["headers"]
    assert kwargs["json"]["country"] == "united arab emirates"
    assert kwargs["json"]["query"] == "pay RTA fine"


def test_optional_key_replaces_keyless_header(settings):
    http = _Http()
    settings = dataclasses.replace(settings, secrets={"TAVILY_API_KEY": "test-value"})
    asyncio.run(tavily_search.search(_ctx(settings, http), "pay RTA fine"))

    headers = http.calls[0][1]["headers"]
    assert headers["Authorization"] == "Bearer test-value"
    assert "X-Tavily-Access-Mode" not in headers


def test_repeat_within_24h_uses_cache_no_http(settings):
    http = _Http()
    asyncio.run(tavily_search.search(_ctx(settings, http), "pay RTA fine"))
    again = asyncio.run(tavily_search.search(_ctx(settings, http, T0 + timedelta(hours=23)), "pay RTA fine"))

    assert len(http.calls) == 1
    assert again["status"] == "cached" and len(again["results"]) == 3
    asyncio.run(tavily_search.search(_ctx(settings, http, T0 + timedelta(hours=25)), "pay RTA fine"))
    assert len(http.calls) == 2


def test_budget_used_makes_no_http_and_says_so(settings):
    cfg = dataclasses.replace(settings.sources["tavily"], budget_per_day=1)
    settings = dataclasses.replace(settings, sources={**settings.sources, "tavily": cfg})
    http = _Http()
    ctx = _ctx(settings, http)
    asyncio.run(tavily_search.search(ctx, "pay RTA fine"))
    blocked = asyncio.run(tavily_search.search(ctx, "Salik recharge"))

    assert len(http.calls) == 1
    assert blocked["status"] == "error" and blocked["error"] == "budget"
    assert tavily_search.not_checked(blocked) == "Not checked: web search — request budget used"


def test_failure_shows_cached_results_time(settings):
    asyncio.run(tavily_search.search(_ctx(settings, _Http()), "pay RTA fine"))
    failed = asyncio.run(tavily_search.search(_ctx(settings, _Http(429), T0 + timedelta(hours=30)), "pay RTA fine"))

    assert failed["status"] == "error" and failed["error"] == "http_429"
    assert failed["cached_at"] == "2026-11-19T08:00:00Z" and len(failed["results"]) == 3


def test_run_once_covers_every_brand_query_within_daily_budget(settings):
    queries = {q for b in settings.brands for q in b.search_queries}
    assert len(queries) >= 5
    http = _Http()
    summary = asyncio.run(tavily_search.run_once(_ctx(settings, http)))

    assert len(http.calls) == len(queries) <= settings.sources["tavily"].budget_per_day
    assert summary["queries"] == len(queries) and summary["error"] is None
    row = asyncio.run(db.run(lambda c: dict(c.execute("SELECT status FROM sources WHERE name = 'tavily'").fetchone())))
    assert row["status"] == "ok"


def test_run_once_stops_on_rate_limit(settings):
    http = _Http(429)
    summary = asyncio.run(tavily_search.run_once(_ctx(settings, http)))

    assert len(http.calls) == 1 and summary["error"] == "http_429"
    rows = {
        "tavily": asyncio.run(
            db.run(lambda c: dict(c.execute("SELECT * FROM sources WHERE name = 'tavily'").fetchone()))
        )
    }
    entry = routes._search_source(rows)
    assert entry["state"] == "amber" and "rate limit reached" in entry["status"]


def test_web_search_button_runs_search_and_returns_to_feed(settings, monkeypatch):
    seen = []

    async def fake_run_once(ctx):
        seen.append(ctx.pool)
        return {"queries": 0, "error": None}

    monkeypatch.setattr(tavily_search, "run_once", fake_run_once)
    with TestClient(app_module.create_app(background=False), follow_redirects=False) as client:
        assert "Web search" in client.get("/").text
        response = client.post("/search/run")

    assert response.status_code == 303 and response.headers["location"] == "/" and seen == ["manual"]
