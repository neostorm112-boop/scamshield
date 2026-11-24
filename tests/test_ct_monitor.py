import asyncio
import json
from datetime import UTC, datetime

from scamshield import app as app_module
from scamshield import db
from scamshield.connectors import ct_tiled
from scamshield.contracts import Ctx, Settings, SourceCfg
from scamshield.web import routes

NOW = "2026-11-19T08:00:00Z"
NOW_EPOCH = datetime(2026, 11, 19, 8, tzinfo=UTC).timestamp()
LOG = "https://ct.example"


class _Response:
    def __init__(self, status_code, text=""):
        self.status_code, self.text = status_code, text


class _Http:
    """Fake tiled log: checkpoint sizes are served in order (the last one repeats); partial tile URLs may answer 403."""

    def __init__(self, sizes, age_s=60, partial_403=False):
        self.sizes, self.age_s, self.partial_403, self.urls = list(sizes), age_s, partial_403, []

    async def get(self, url, **kwargs):
        self.urls.append(url)
        if url.endswith("/checkpoint"):
            size = self.sizes.pop(0) if len(self.sizes) > 1 else self.sizes[0]
            return _Response(200, f"log\n{size}\nhash\n")
        path = url.split("/tile/names/")[1]
        if ".p/" in path and self.partial_403:
            return _Response(403)
        width = int(path.split(".p/")[1]) if ".p/" in path else 256
        ms = int((NOW_EPOCH - self.age_s) * 1000)
        return _Response(200, "\n".join(json.dumps({"Timestamp": ms, "DNS": ["x.example"]}) for _ in range(width)))


class _Budget:
    async def take(self, source, pool="auto"):
        return True


def _settings(**extra):
    cfg = {
        "recheck_hours": 6,
        "max_lag_minutes": 60,
        "max_tiles_per_cycle": 20,
        "tile_concurrency": 4,
        "amber_lag_minutes": 5,
        "logs": [LOG],
        **extra,
    }
    return Settings(
        brands=[],
        sources={"ct_tiled": SourceCfg("connector", extra=cfg)},
        scoring={},
        shared_infra={},
        data_dir="",
        port=0,
        db_path="",
        evidence_dir="",
        secrets={},
    )


def _run(http, cursor, monkeypatch, **extra):
    stored = []

    async def store(candidates, connector, cursor, recheck_s):
        stored.append(cursor)

    monkeypatch.setattr(ct_tiled.intake, "store_candidates", store)
    monkeypatch.setattr(ct_tiled, "match", lambda name, brands: None)
    ctx = Ctx(settings=_settings(**extra), http=http, resolver=None, budget=_Budget(), pool="auto", now=lambda: NOW)
    return asyncio.run(ct_tiled.run_once(LOG, cursor, ctx)), stored


def test_three_tiles_behind_is_caught_up_in_one_cycle_saving_cursor_per_tile(monkeypatch):
    result, stored = _run(_Http([1024]), "256", monkeypatch)

    assert result["status"] == "ok" and result["cursor"] == "1024"
    assert stored == ["512", "768", "1024"]


def test_tiles_are_fetched_in_one_batch_per_checkpoint(monkeypatch):
    http = _Http([2048])
    _run(http, "0", monkeypatch, tile_concurrency=4)

    assert [u.endswith("/checkpoint") for u in http.urls].count(
        True
    ) == 3  # 8 tiles: batch of 4, batch of 4, then the tail check


def test_tiles_per_cycle_is_limited_by_config(monkeypatch):
    result, stored = _run(_Http([1024]), "0", monkeypatch, max_tiles_per_cycle=2)

    assert result["cursor"] == "512" and stored == ["256", "512"]


def test_403_on_partial_tile_rereads_checkpoint_and_takes_full_tile(monkeypatch):
    http = _Http([300, 512], partial_403=True)
    result, stored = _run(http, "256", monkeypatch)

    assert result["status"] == "ok" and "error" not in result
    assert result["cursor"] == "512" and stored == ["512"]
    assert any(url.endswith("/tile/names/001") for url in http.urls)


def test_403_on_partial_tile_still_partial_waits_for_next_poll(monkeypatch):
    result, stored = _run(_Http([300], partial_403=True), "256", monkeypatch)

    assert result["status"] == "ok" and result["cursor"] == "256" and stored == []


def test_lag_over_max_jumps_to_tail_and_reports_skip(monkeypatch):
    http = _Http([1024], age_s=3 * 3600)
    result, stored = _run(http, "0", monkeypatch)

    assert result["cursor"] == "1024" and stored == ["1024"]
    skipped = result["skipped"]
    assert (skipped["from"], skipped["to"]) == (0, 1024)
    assert skipped["from_ts"] == "2026-11-19T05:00:00Z"
    assert (
        len([u for u in http.urls if "/tile/" in u]) <= 4
    )  # no backfill of the skipped range: only the one prefetch batch (tile_concurrency)


def _cycles(tmp_path, results, times, name="a"):
    db.init(str(tmp_path / name / "scamshield.db"))
    for result, now in zip(results, times, strict=True):
        asyncio.run(db.run(app_module._record_ct_cycle, LOG, result, now))
    rows = asyncio.run(db.run(routes._source_rows))
    return routes._ct_sources(_settings(), rows, times[-1])[0]


def _ok(cursor, size, last_ts=NOW, **extra):
    return {"status": "ok", "records": 0, "cursor": str(cursor), "size": size, "last_ts": last_ts, **extra}


def test_strip_shows_rate_lag_and_ok(tmp_path):
    strip = _cycles(tmp_path, [_ok(1000, 1000), _ok(1170, 1180, "2026-11-19T07:59:55Z")], [NOW_EPOCH - 10, NOW_EPOCH])

    assert strip["state"] == "ok"
    assert strip["rate"] == 17.0
    assert strip["lag_entries"] == 10 and strip["lag_minutes"] < 1


def test_strip_amber_when_lag_minutes_over_threshold(tmp_path):
    strip = _cycles(tmp_path, [_ok(0, 5000, "2026-11-19T07:40:00Z")], [NOW_EPOCH])

    assert strip["state"] == "amber" and strip["lag_minutes"] == 20


def test_strip_amber_after_skip_and_says_which_entries(tmp_path):
    skipped = {"from": 10, "to": 900, "from_ts": "2026-11-19T05:00:00Z", "to_ts": NOW}
    strip = _cycles(tmp_path, [_ok(900, 900, skipped=skipped)], [NOW_EPOCH])

    assert strip["state"] == "amber"
    assert "skipped entries 10–900" in strip["status"] and "05:00" in strip["status"]


def test_strip_error_is_human_text_amber_then_red_after_10_minutes(tmp_path):
    err = {"status": "error", "records": 0, "cursor": "1", "error": "timeout"}
    amber = _cycles(tmp_path, [err], [NOW_EPOCH])
    assert amber["state"] == "amber" and "no answer (timeout)" in amber["status"] and "error:" not in amber["status"]

    red = _cycles(tmp_path, [err, err], [NOW_EPOCH - 601, NOW_EPOCH], "b")
    assert red["state"] == "red"
