import asyncio
import dataclasses
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from scamshield import app as app_module
from scamshield import config, db, runtime, sources
from scamshield.connectors import feeds
from scamshield.enrich import feed_match
from scamshield.web import routes

FIX = Path(__file__).parent / "fixtures" / "feeds"
T1, T2 = "2026-11-19T08:00:00Z", "2026-11-19T14:00:00Z"
FILES = {
    "phishing_database": "phishing_database.txt",
    "phishing_army": "phishing_army.txt",
    "openphish": "openphish.txt",
}


class _Stream:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def aiter_bytes(self):
        for i in range(0, len(self._body), 7):
            yield self._body[i : i + 7]


class _Http:
    """Recorded list files by feed url; a feed mapped to None answers 500, a feed missing from `down_all` mode fails to connect."""

    def __init__(self, settings, files, down=False):
        urls = settings.sources["feeds"].extra["urls"]
        self.by_url = {urls[name]: (FIX / file).read_bytes() if file else None for name, file in files.items()}
        self.down = down

    def stream(self, method, url, **kwargs):
        if self.down:
            raise httpx.ConnectError("offline")
        body = self.by_url[url]
        return _Stream(500 if body is None else 200, body or b"")


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    settings = config.load()
    # the code still supports OpenPhish; the live config left it out (its terms bar public display), the tests keep the third feed
    settings.sources["feeds"].extra["urls"].setdefault(
        "openphish", "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
    )
    db.init(settings.db_path)
    return settings


def _ctx(settings, http, now):
    return dataclasses.replace(runtime.make_ctx(settings, http, "auto"), now=lambda: now)


def _load(settings, now, **kwargs):
    files = {**FILES, **kwargs.pop("files", {})}
    return asyncio.run(feeds.run_once(_ctx(settings, _Http(settings, files, **kwargs), now)))


def _rows(settings, sql):
    return sqlite3.connect(settings.db_path).execute(sql).fetchall()


def test_first_load_is_baseline_and_only_brand_lookalikes_become_domains(settings):
    _load(settings, T1)

    assert _rows(settings, "SELECT count(*) FROM feed_index")[0][0] == 8  # every listed domain, deduplicated
    domains = dict(_rows(settings, "SELECT fqdn, found_by FROM domains"))
    assert domains == {
        "e1isalat-pay.com": "baseline",
        "salik-recharge.top": "baseline",
        "rta-fines.live": "baseline",
        "aramex-1f3a9c.ingress-earth.ewp.live": "baseline",
    }
    assert {row[0] for row in _rows(settings, "SELECT priority FROM jobs")} == {-10}


def test_openphish_path_gives_short_keyword_context_and_is_stored_in_urls(settings):
    _load(settings, T1, files={"openphish": "openphish_du.txt"})

    domains = dict(_rows(settings, "SELECT fqdn, found_by FROM domains"))
    assert domains["du.xyz"] == "baseline" and "du.ac.bd" not in domains and "abc.du.r.appspot.com" not in domains
    assert _rows(
        settings, "SELECT u.url, u.source FROM urls u JOIN domains d ON d.id = u.domain_id WHERE d.fqdn = 'du.xyz'"
    ) == [("https://du.xyz/du-recharge/pay", "baseline")]


def test_feed_hides_baseline_by_default_with_explanation(settings):
    _load(settings, T1)

    with TestClient(app_module.create_app(background=False)) as client:
        page = client.get("/").text
        assert "e1isalat-pay.com" not in page and "loaded as baseline" in page
        assert "e1isalat-pay.com" in client.get("/?baseline=1").text


def test_second_load_new_domain_is_checked_and_first_listed_kept(settings):
    _load(settings, T1)
    _load(settings, T2, files={"phishing_database": "phishing_database_v2.txt"})

    domains = dict(_rows(settings, "SELECT fqdn, found_by FROM domains"))
    assert domains["dubaipolice-fine.com"] == "feeds"
    assert "new.bad-site.net" not in domains  # listed, but not a brand lookalike
    assert _rows(settings, "SELECT priority FROM jobs WHERE target = 'dubaipolice-fine.com'") == [(0,)]
    listed = dict(_rows(settings, "SELECT domain, first_listed_at FROM feed_index"))
    assert listed["e1isalat-pay.com"] == T1 and listed["dubaipolice-fine.com"] == T2


def test_failed_download_marks_stale_keeps_old_index_and_feed_answers(settings):
    _load(settings, T1)
    before = _rows(settings, "SELECT domain, first_listed_at FROM feed_index ORDER BY domain")

    _load(settings, T2, down=True)

    assert _rows(settings, "SELECT domain, first_listed_at FROM feed_index ORDER BY domain") == before
    assert _rows(settings, "SELECT status FROM sources WHERE name = 'feeds:openphish'") == [("stale",)]
    with TestClient(app_module.create_app(background=False)) as client:
        assert client.get("/").status_code == 200
        strip = routes._all_sources(client.app.state.settings, asyncio.run(db.run(routes._source_rows)))
        assert any(s["name"] == "phishing_army" for s in strip) and any(
            "(stale)" in s["status"] for s in strip
        )  # the app reloads the live config (no OpenPhish)


def test_one_failed_feed_keeps_its_old_entries(settings):
    _load(settings, T1)
    _load(settings, T2, files={"openphish": None})

    assert _rows(settings, "SELECT sources FROM feed_index WHERE domain = 'evil.example'") == [("openphish",)]


def _match(settings, fqdn, now):
    return asyncio.run(feed_match.run(fqdn, _ctx(settings, None, now)))


def test_feed_match_names_the_list_and_times(settings):
    _load(settings, T1)

    fact = _match(settings, "login.e1isalat-pay.com", "2026-11-19T09:00:00Z")[0]

    assert (fact.type, fact.status, fact.source) == ("in_feed", "ok", "feed_match")
    assert fact.value["feeds"] == ["phishing_database"] and fact.value["first_listed_at"] == T1
    assert fact.fetched_at == T1
    clean = _match(settings, "example.org", "2026-11-19T09:00:00Z")[0]
    assert clean.status == "ok" and clean.value["listed"] is False


def test_feed_match_without_index_is_not_checked_not_unlisted(settings):
    fact = _match(settings, "example.org", T1)[0]

    assert fact.status == "error" and fact.error == "not_loaded" and fact.value == {}
    assert sources.not_checked_text(fact.source, fact.error).startswith("Not checked")


def test_feed_match_with_old_index_says_stale_for_unlisted_domain(settings):
    _load(settings, T1)

    fact = _match(settings, "example.org", "2026-11-21T09:00:00Z")[0]

    assert fact.status == "error" and fact.error == "stale"


def test_oversized_list_is_refused_with_reason(settings):
    ctx = _ctx(settings, _Http(settings, FILES), T1)
    url = settings.sources["feeds"].extra["urls"]["phishing_database"]

    result = asyncio.run(sources.fetch_text_limited(ctx, "feeds", url, 10))

    assert result == sources.SourceError("feeds", "too_large")


def test_feed_that_failed_on_first_load_gets_its_own_baseline(settings):
    _load(settings, T1, files={"openphish": None})
    _load(settings, T2)

    domains = dict(_rows(settings, "SELECT fqdn, found_by FROM domains"))
    assert domains["aramex-1f3a9c.ingress-earth.ewp.live"] == "baseline"
