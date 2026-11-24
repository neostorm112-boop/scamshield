import asyncio
import dataclasses
import sqlite3
from pathlib import Path

import pytest

from scamshield import config, db, runtime, sources
from scamshield.connectors import ct_tiled, nrd
from scamshield.web import routes

NOW = "2026-11-22T10:00:00Z"
TODAY, YESTERDAY = "2026-11-22", "2026-11-21"


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    settings = config.load()
    db.init(settings.db_path)
    nrd._seen.clear()
    nrd._validators.clear()
    ct_tiled._generic.update(hour="", taken=0, seen=set(), dropped=0, reported=0)
    nrd._generic_nrd.update(hour="", taken=0, seen=set(), dropped=0, reported=0)
    return settings


def _run(settings, files, monkeypatch, now=NOW):
    """One pull; `files` maps a day to its text (or a 1-tuple with an error reason); returns the result and the URLs asked for."""
    asked = []

    async def fake(ctx, source, url, max_bytes, validators=None):
        asked.append(url)
        value = files.get(url.rsplit("/", 1)[-1].removesuffix(".txt"), ("http_404",))
        return sources.SourceError(source, value[0]) if isinstance(value, tuple) else value

    monkeypatch.setattr(sources, "fetch_text_limited", fake)
    ctx = dataclasses.replace(runtime.make_ctx(settings, None, "auto"), now=lambda: now)
    return asyncio.run(nrd.run_once(ctx)), asked


def _query(settings, sql):
    return sqlite3.connect(settings.db_path).execute(sql).fetchall()


def _spy_classify(monkeypatch):
    calls, real = [], nrd._classify
    monkeypatch.setattr(nrd, "_classify", lambda names, ctx: calls.append(names) or real(names, ctx))
    return calls


def test_parse_skips_noise_and_keeps_idn_as_punycode():
    text = "\n# comment\n   \nExample.COM\nexample.com\nbücher.de\nno-dot\nxn--80ak6aa92e.com.\nbad name.com\n"
    assert [name for _, name in nrd._parse(text, set())] == ["example.com", "xn--80ak6aa92e.com"]


def test_uae_brand_name_becomes_candidate_and_status_is_ok(settings, monkeypatch):
    result, asked = _run(settings, {TODAY: "salik.enterprises\nplain-shop.com\n", YESTERDAY: ""}, monkeypatch)

    assert result == {"candidates": 1, "error": None}
    assert asked == [f"https://smet.cz/nrd/data/daily/{YESTERDAY}.txt", f"https://smet.cz/nrd/data/daily/{TODAY}.txt"]
    assert _query(settings, "SELECT fqdn, brand_id IS NOT NULL FROM domains WHERE found_by = 'nrd'") == [
        ("salik.enterprises", 1)
    ]
    assert _query(settings, "SELECT status FROM sources WHERE name = 'nrd'") == [("ok",)]


def test_second_pull_filters_only_new_lines_even_if_sorted_file_grows_in_the_middle(settings, monkeypatch):
    _run(settings, {TODAY: "salik.enterprises\n"}, monkeypatch)
    calls = _spy_classify(monkeypatch)
    grown = "a-plain.com\nsalik.enterprises\nsalik-pay.top\n"

    _run(settings, {TODAY: grown}, monkeypatch)
    assert calls == [["a-plain.com", "salik-pay.top"]]

    nrd._seen.clear()  # a restart: the hashes come back from the file
    _run(settings, {TODAY: grown}, monkeypatch)
    assert len(calls) == 1


def test_day_change_reads_rest_of_yesterday_and_drops_older_state(settings, monkeypatch):
    _run(settings, {TODAY: "one.com\n", YESTERDAY: "old-a.com\n"}, monkeypatch)
    assert {p.name for p in Path(settings.data_dir).glob("nrd_seen_*")} == {
        f"nrd_seen_{YESTERDAY}.bin",
        f"nrd_seen_{TODAY}.bin",
    }
    calls = _spy_classify(monkeypatch)

    # next day: the file that was "today" is now "yesterday" and got a late tail; the day before it is forgotten
    _run(
        settings,
        {"2026-11-23": "two.com\n", TODAY: "one.com\nlate-tail.com\n"},
        monkeypatch,
        now="2026-11-23T00:30:00Z",
    )

    assert calls == [["late-tail.com"], ["two.com"]]
    assert {p.name for p in Path(settings.data_dir).glob("nrd_seen_*")} == {
        f"nrd_seen_{TODAY}.bin",
        "nrd_seen_2026-11-23.bin",
    }


def test_generic_names_have_their_own_hourly_budget_and_apex_dedup(settings, monkeypatch):
    settings.scoring["generic"]["nrd_budget_per_hour"] = 1
    result, _ = _run(
        settings,
        {TODAY: "fairplay-login.sbs\nlogin.fairplay-login.sbs\nvery-account-secure.icu\ng-pay.top\n"},
        monkeypatch,
    )

    assert result["candidates"] == 1
    assert len(_query(settings, "SELECT fqdn FROM domains WHERE found_by = 'nrd'")) == 1
    assert (
        nrd._generic_nrd["dropped"] >= 1 and ct_tiled._generic["taken"] == 0
    )  # its own pool: the CT hour is untouched


def test_download_error_is_status_and_heartbeat_not_exception(settings, monkeypatch):
    result, _ = _run(settings, {TODAY: ("timeout",)}, monkeypatch)

    assert result == {"candidates": 0, "error": "timeout"}  # the missing yesterday file (404) is not an error
    assert _query(settings, "SELECT status FROM sources WHERE name = 'nrd'") == [("error: timeout",)]
    assert _query(settings, "SELECT ok, error FROM heartbeats WHERE loop = 'nrd'") == [(0, "timeout")]


def test_source_is_listed_on_screen(settings):
    rows = {"nrd": {"name": "nrd", "status": "ok", "last_success_at": NOW, "last_error": None}}
    entry = next(e for e in routes._all_sources(settings, rows) if e["name"] == "new domains (smet.cz)")
    assert entry["state"] == "ok"


def test_nrd_brand_facts_are_superseded_on_recheck():
    from scamshield import db as _db

    assert "nrd" in _db.NAME_BRAND_SOURCES  # a brand-rule change re-evaluates NRD finds like CT ones


def test_unchanged_file_is_not_an_error(settings, monkeypatch):
    """smet.cz answers 304 to a conditional request: nothing new, the source stays ok."""
    result, _ = _run(settings, {TODAY: ("not_modified",), YESTERDAY: ("not_modified",)}, monkeypatch)

    assert result == {"candidates": 0, "error": None}


def test_conditional_get_sends_validators_and_maps_304(monkeypatch):
    import httpx

    from scamshield.contracts import Ctx, Settings

    sent = []

    class Stream:
        def __init__(self, status, headers):
            self.status_code, self.headers = status, httpx.Headers(headers)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def aiter_bytes(self):
            yield b"example.com\n"

    class Http:
        def stream(self, method, url, headers=None, **kwargs):
            sent.append(headers)
            return (
                Stream(304, {})
                if headers
                else Stream(200, {"ETag": '"v1"', "Last-Modified": "Sun, 22 Nov 2026 10:00:00 GMT"})
            )

    class Budget:
        async def take(self, source, pool="auto"):
            return True

    ctx = Ctx(
        Settings([], {"nrd": type("S", (), {"timeout_s": 8, "extra": {}})()}, {}, {}, "", 0, "", "", {}),
        Http(),
        None,
        Budget(),
        "auto",
        lambda: NOW,
    )
    validators = {}
    url = "https://example.org/2026-11-22.txt"
    first = asyncio.run(sources.fetch_text_limited(ctx, "nrd", url, 1000, validators))
    second = asyncio.run(sources.fetch_text_limited(ctx, "nrd", url, 1000, validators))

    assert first == "example.com\n"
    assert sent[1] == {"If-None-Match": '"v1"', "If-Modified-Since": "Sun, 22 Nov 2026 10:00:00 GMT"}
    assert isinstance(second, sources.SourceError) and second.reason == "not_modified"
