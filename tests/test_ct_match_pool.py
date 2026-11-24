"""Brand matching of CT names in worker processes: same verdicts as in the main process, cached per fqdn, falls back when workers die."""

import asyncio
import dataclasses

import pytest

from scamshield import config
from scamshield.connectors import ct_tiled
from scamshield.contracts import Ctx

NAMES = [
    "rta-fines-pay.top",
    "www.salik-topup.xyz",
    "dubai.aeizt.top",
    "verify-account-kyc.top",
    "google.com",
    "mail.example.org",
    "emiratesnbd-secure.online",
    "rta.ae",
    "parkin-dubai.click",
    "random-shop-42.store",
]


def _ctx(settings):
    return Ctx(settings, None, None, None, "auto", lambda: "2026-11-22T12:00:00Z")


def _settings(processes, min_names=1):
    base = config.load()
    cfg = base.sources["ct_tiled"]
    extra = {**cfg.extra, "match_processes": processes, "match_pool_min_names": min_names}
    return dataclasses.replace(base, sources={**base.sources, "ct_tiled": dataclasses.replace(cfg, extra=extra)})


@pytest.fixture(autouse=True)
def _fresh_matcher():
    ct_tiled._reset_pool()
    ct_tiled._matcher.update(settings=None, cache={}, off_until=0.0)
    yield
    ct_tiled._reset_pool()
    ct_tiled._matcher.update(settings=None, cache={}, off_until=0.0)


def test_pool_gives_the_same_verdicts_as_the_main_process():
    names = NAMES * 30  # repeats, as certificate + precertificate
    inline = asyncio.run(ct_tiled._classify_names(_ctx(_settings(0)), names))
    pooled = asyncio.run(ct_tiled._classify_names(_ctx(_settings(2)), names))
    assert pooled == inline
    assert inline["rta-fines-pay.top"][0] == "brand" and inline["google.com"] is None
    assert any(v and v[0] == "generic" for v in inline.values())


def test_small_batches_stay_in_the_main_process():
    settings = _settings(2, min_names=200)
    asyncio.run(ct_tiled._classify_names(_ctx(settings), NAMES))
    assert ct_tiled._matcher["pool"] is None


def test_each_name_is_matched_once(monkeypatch):
    calls = []
    real = ct_tiled.match
    monkeypatch.setattr(ct_tiled, "match", lambda fqdn, brands: calls.append(fqdn) or real(fqdn, brands))
    ctx = _ctx(_settings(0))
    asyncio.run(ct_tiled._classify_names(ctx, NAMES + NAMES))
    asyncio.run(ct_tiled._classify_names(ctx, NAMES))
    assert sorted(calls) == sorted(NAMES)


def test_new_settings_drop_the_cache():
    asyncio.run(ct_tiled._classify_names(_ctx(_settings(0)), NAMES))
    asyncio.run(ct_tiled._classify_names(_ctx(_settings(0)), NAMES[:1]))
    assert list(ct_tiled._matcher["cache"]) == NAMES[:1]


def test_dead_workers_fall_back_to_the_main_process(monkeypatch):
    class _Broken:
        def submit(self, *args, **kwargs):
            raise RuntimeError("cannot schedule new futures after shutdown")

        def shutdown(self, **kwargs):
            pass

    monkeypatch.setattr(ct_tiled, "_pool", lambda processes, args: _Broken())
    out = asyncio.run(ct_tiled._classify_names(_ctx(_settings(2)), NAMES))
    assert ct_tiled._matcher["off_until"] > 0  # no respawn for every tile while workers are failing
    expected = asyncio.run(ct_tiled._classify_names(_ctx(_settings(0)), NAMES))
    assert out == expected


def test_step_with_pool_matches_step_inline(monkeypatch):
    """Whole tile through _step: candidates (incl. the hourly brandless slots) do not depend on where matching ran."""
    import json

    class _Resp:
        def __init__(self, text):
            self.status_code, self.text, self.headers = 200, text, {}

    names = [f"verify-acc{i}.top" for i in range(40)] + NAMES * 20

    async def fake_text(ctx, source, url, headers=None):
        if url.endswith("/checkpoint"):
            return f"log.example\n{len(names)}\nhash\n"
        return "\n".join(json.dumps({"Timestamp": 1763812800000 + i, "DNS": [n]}) for i, n in enumerate(names))

    monkeypatch.setattr(ct_tiled.sources, "fetch_text", fake_text)
    results = []
    for processes in (0, 2):
        ct_tiled._generic.update(hour="", taken=0, seen=set(), dropped=0, reported=0)
        settings = _settings(processes)
        settings.sources["ct_tiled"].extra["max_lag_minutes"] = 10**9
        step = asyncio.run(ct_tiled._step("0", 256, _ctx(settings), "https://ct.example"))
        results.append([(c.value, c.metadata) for c in step.batch.candidates])
    assert results[0] == results[1] and results[0]
