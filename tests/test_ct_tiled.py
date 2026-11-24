import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

from scamshield.contracts import Ctx, Settings, SourceCfg


class _Response:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text

    def json(self):
        return json.loads(self.text)


class _Http:
    def __init__(self):
        self.urls = []

    async def get(self, url, **kwargs):
        self.urls.append(url)
        if url.endswith("/checkpoint"):
            return _Response(200, "log.example\n2\nhash\n")
        entries = [
            {"Timestamp": 1760000000000, "DNS": ["e1isalat-pay.com"]},
            {"Timestamp": 1760000001000, "DNS": ["rta.ae"]},
        ]
        return _Response(200, "\n".join(json.dumps(entry) for entry in entries))


class _Budget:
    async def take(self, source, pool="auto"):
        return True

    async def remaining(self, source):
        return {}


def _ctx(http):
    settings = Settings(
        brands=[],
        sources={
            "ct_tiled": SourceCfg(
                "connector",
                extra={"recheck_hours": 24, "max_lag_minutes": 10**9, "max_tiles_per_cycle": 20, "tile_concurrency": 4},
            )
        },
        scoring={},
        shared_infra={},
        data_dir="",
        port=0,
        db_path="",
        evidence_dir="",
        secrets={},
    )
    return Ctx(
        settings=settings, http=http, resolver=None, budget=_Budget(), pool="auto", now=lambda: "2026-11-19T08:00:00Z"
    )


def test_fetch_emits_only_brand_matches_and_advances_cursor(monkeypatch):
    from scamshield.connectors import ct_tiled

    monkeypatch.setattr(
        ct_tiled,
        "match",
        lambda name, brands: (
            {
                "brand": "etisalat",
                "method": "homoglyph",
                "position": "registrable",
                "context": "name",
                "mode": "ct",
                "score": 0.8,
                "tokens": ["x"],
            }
            if name == "e1isalat-pay.com"
            else None
        ),
    )
    http = _Http()
    batch = asyncio.run(ct_tiled.fetch("0", None, 256, _ctx(http), "https://ct.example"))

    assert batch.status == "ok"
    assert batch.next_cursor == "2"
    assert [candidate.value for candidate in batch.candidates] == ["e1isalat-pay.com"]
    assert batch.candidates[0].source == "ct_tiled"
    assert batch.candidates[0].metadata["brand"] == "etisalat"
    assert (
        batch.candidates[0].metadata["method"],
        batch.candidates[0].metadata["position"],
        batch.candidates[0].metadata["context"],
    ) == ("homoglyph", "registrable", "name")
    assert "tokens" not in batch.candidates[0].metadata
    assert http.urls[-1].endswith("/tile/names/000.p/2")


def test_first_start_sets_cursor_at_tip_without_backfill(monkeypatch):
    from scamshield.connectors import ct_tiled

    http = _Http()
    batch = asyncio.run(ct_tiled.fetch(None, None, 256, _ctx(http), "https://ct.example"))

    assert batch.status == "ok"
    assert batch.next_cursor == "2"
    assert http.urls == ["https://ct.example/checkpoint"]


def test_run_once_saves_candidates_cursor_and_source_status(monkeypatch):
    from scamshield.connectors import ct_tiled
    from scamshield.contracts import Candidate, CandidateBatch

    saved = {}

    async def step(cursor, limit, ctx, log_url, size=None, tiles=None):
        batch = CandidateBatch(
            [Candidate("e1isalat-pay.com", "ct_tiled", "2026-11-19T08:00:00Z", "LIVE", {"brand": "etisalat"})],
            "17",
            "ok",
        )
        return ct_tiled._Step(batch, 17)

    async def store(candidates, connector, cursor, recheck_s):
        saved.update(candidates=candidates, connector=connector, cursor=cursor)

    monkeypatch.setattr(ct_tiled, "_step", step)
    monkeypatch.setattr(ct_tiled.intake, "store_candidates", store)
    result = asyncio.run(ct_tiled.run_once("https://ct.example", "10", _ctx(_Http())))

    assert result == {"status": "ok", "records": 1, "cursor": "17", "size": 17, "last_ts": None}
    assert saved["connector"] == "https://ct.example"
    assert saved["cursor"] == "17"


def test_connect_timeout_is_error_timeout_and_cycle_continues(tmp_path):
    import sqlite3

    import httpx

    from scamshield import app as app_module
    from scamshield import db
    from scamshield.connectors import ct_tiled

    class TimeoutHttp:
        async def get(self, url, **kwargs):
            raise httpx.ConnectTimeout("slow")

    ctx = _ctx(TimeoutHttp())
    result = asyncio.run(ct_tiled.run_once("https://ct.example", "10", ctx))
    assert result["status"] == "error"
    assert result["error"] == "timeout"

    db.init(str(tmp_path / "scamshield.db"))
    asyncio.run(db.run(app_module._record_ct_cycle, "https://ct.example", result))
    row = sqlite3.connect(tmp_path / "scamshield.db").execute("SELECT status, last_error FROM sources").fetchone()
    assert row == ("error: timeout", "timeout")


def test_fetch_with_small_limit_loses_no_entries(monkeypatch):
    from scamshield.connectors import ct_tiled

    monkeypatch.setattr(
        ct_tiled,
        "match",
        lambda name, brands: (
            {"brand": "b", "method": "m", "score": 1} if name in ("e1isalat-pay.com", "rta.ae") else None
        ),
    )
    http = _Http()
    first = asyncio.run(ct_tiled.fetch("0", None, 1, _ctx(http), "https://ct.example"))
    second = asyncio.run(ct_tiled.fetch(first.next_cursor, None, 1, _ctx(http), "https://ct.example"))

    assert first.next_cursor == "1" and [c.value for c in first.candidates] == ["e1isalat-pay.com"]
    assert second.next_cursor == "2" and [c.value for c in second.candidates] == ["rta.ae"]


LOG_LIST = json.loads((Path(__file__).parent.parent / "fixtures/ct/log_list_2026-11-20.json").read_text())
LE = "https://mon.{}.ct.letsencrypt.org/{}"


def test_select_logs_picks_expiry_shards_of_allowed_operators_for_today():
    from scamshield.connectors import ct_tiled

    logs = ct_tiled.select_logs(LOG_LIST, datetime(2026, 11, 20, tzinfo=UTC), ["Let's Encrypt"], 100)

    assert logs == sorted(LE.format(name, shard) for name in ("willow", "sycamore") for shard in ("2026h2", "2027h1"))


def test_select_logs_skips_logs_that_are_not_usable():
    from scamshield.connectors import ct_tiled

    logs = ct_tiled.select_logs(LOG_LIST, datetime(2027, 12, 20, tzinfo=UTC), ["Let's Encrypt"], 100)

    assert LE.format("willow", "2028h1") not in logs  # qualified, not usable


class _ListHttp:
    def __init__(self, payload):
        self.payload = payload

    async def get(self, url, **kwargs):
        if self.payload is None:
            raise httpx.ConnectError("down")
        return _Response(200, json.dumps(self.payload))


def _list_ctx(payload):
    ctx = _ctx(_ListHttp(payload))
    ctx.settings.sources["ct_tiled"].extra.update(log_operators=["Let's Encrypt"], expiry_window_days=100, logs=["cfg"])
    return ctx


def test_resolve_logs_falls_back_to_previous_then_config():
    from scamshield.connectors import ct_tiled

    assert len(asyncio.run(ct_tiled.resolve_logs(_list_ctx(LOG_LIST)))) == 4
    assert asyncio.run(ct_tiled.resolve_logs(_list_ctx(None), ["prev"])) == ["prev"]
    assert asyncio.run(ct_tiled.resolve_logs(_list_ctx(None))) == ["cfg"]


def test_new_log_starts_at_checkpoint_tail_without_reading_tiles(monkeypatch):
    from scamshield.connectors import ct_tiled

    async def store(*args):
        pass

    monkeypatch.setattr(ct_tiled.intake, "store_candidates", store)

    http = _Http()
    result = asyncio.run(ct_tiled.run_once("https://ct.example", None, _ctx(http)))

    assert result["cursor"] == "2" and result["records"] == 0
    assert not [url for url in http.urls if "/tile/" in url]


def test_hung_tile_read_ends_cycle_with_error_inside_the_deadline():
    from scamshield.connectors import ct_tiled

    class _Hung:
        async def get(self, url, **kwargs):
            if url.endswith("/checkpoint"):
                return _Response(200, "log.example\n600\nhash\n")
            await asyncio.Event().wait()  # tiles never answer, like a body that trickles forever

    ctx = _ctx(_Hung())
    ctx.settings.sources["ct_tiled"].extra["deadline_s"] = 0.2
    result = asyncio.run(asyncio.wait_for(ct_tiled.run_once("https://ct.example", "10", ctx), timeout=5))

    assert (result["status"], result["error"], result["cursor"]) == ("error", "timeout", "10")


GEOMYS = "https://tuscolo2026h2.skylight.geomys.org"
FAKE_EMAIL = "ct-contact@example.invalid"


def _geomys_list():
    log = {
        "monitoring_url": GEOMYS + "/",
        "state": {"usable": {}},
        "temporal_interval": {"start_inclusive": "2026-07-01T00:00:00Z", "end_exclusive": "2027-01-01T00:00:00Z"},
    }
    le = {
        "monitoring_url": LE.format("willow", "2026h2"),
        "state": {"usable": {}},
        "temporal_interval": log["temporal_interval"],
    }
    return {"operators": [{"name": "Geomys", "tiled_logs": [log]}, {"name": "Let's Encrypt", "tiled_logs": [le]}]}


def _geomys_ctx(email):
    ctx = _list_ctx(_geomys_list())
    ctx.settings.sources["ct_tiled"].extra.update(
        log_operators=["Let's Encrypt", "Geomys"], contact_host_suffixes=["geomys.org"]
    )
    if email:
        ctx.settings.secrets["CT_CONTACT_EMAIL"] = email
    return ctx


def test_geomys_logs_selected_only_with_contact_email():
    from scamshield.connectors import ct_tiled

    assert GEOMYS in asyncio.run(ct_tiled.resolve_logs(_geomys_ctx(FAKE_EMAIL)))
    without = asyncio.run(ct_tiled.resolve_logs(_geomys_ctx(None)))
    assert without == [LE.format("willow", "2026h2")]


def test_contact_email_in_user_agent_only_for_geomys_hosts():
    from scamshield.connectors import ct_tiled

    ctx = _geomys_ctx(FAKE_EMAIL)
    assert FAKE_EMAIL in ct_tiled._headers(ctx, GEOMYS)["User-Agent"]
    assert ct_tiled._headers(ctx, LE.format("willow", "2026h2")) is None
    assert ct_tiled._headers(ctx, "https://skylight.geomys.org.evil.example") is None
    assert ct_tiled._headers(_geomys_ctx(None), GEOMYS) is None


def test_requests_to_geomys_carry_user_agent_and_others_do_not():
    from scamshield.connectors import ct_tiled

    class Http(_Http):
        async def get(self, url, **kwargs):
            self.seen = [*getattr(self, "seen", []), (url, kwargs.get("headers"))]
            return await super().get(url, **kwargs)

    http = Http()
    ctx = _geomys_ctx(FAKE_EMAIL)
    ctx.http = http
    for base in (GEOMYS, "https://ct.example"):
        asyncio.run(ct_tiled.fetch("0", None, 256, ctx, base))

    agents = {url.split("/")[2]: headers for url, headers in http.seen}
    assert FAKE_EMAIL in agents["tuscolo2026h2.skylight.geomys.org"]["User-Agent"]
    assert agents["ct.example"] is None
