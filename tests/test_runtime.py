import asyncio
from datetime import UTC, datetime

from scamshield import config, db, runtime, sources
from scamshield.contracts import SourceCfg


class _Http:
    def __init__(self):
        self.calls = 0

    async def get(self, url, **kwargs):
        self.calls += 1
        raise AssertionError("no HTTP request expected")


def _settings(cfg):
    settings = config.load()
    settings.sources = {"rdap": cfg}
    return settings


def test_pools_are_counted_separately(tmp_path):
    db.init(str(tmp_path / "scamshield.db"))
    budget = runtime.DbBudget(_settings(SourceCfg("enrich", budget_per_hour=3, extra={"reserve_manual": 2})))

    async def take(pool, times):
        return [await budget.take("rdap", pool) for _ in range(times)]

    assert asyncio.run(take("manual", 3)) == [True, True, False]
    assert asyncio.run(take("auto", 2)) == [True, False]


def test_daily_window_limits_too(tmp_path):
    db.init(str(tmp_path / "scamshield.db"))
    budget = runtime.DbBudget(_settings(SourceCfg("enrich", budget_per_day=1)))

    assert asyncio.run(budget.take("rdap", "auto")) is True
    assert asyncio.run(budget.take("rdap", "auto")) is False
    assert asyncio.run(budget.take("dns", "auto")) is True  # source without limits


def test_exhausted_budget_gives_not_checked_fact_and_no_http_request(tmp_path):
    from scamshield.enrich import rdap

    db.init(str(tmp_path / "scamshield.db"))
    settings = _settings(SourceCfg("enrich", budget_per_hour=1, extra={"max_redirects": 3}))
    http = _Http()
    ctx = runtime.make_ctx(settings, http, "manual")
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:00:00Z")
    db_conn = db._conn()
    db_conn.execute("INSERT INTO budgets (source, pool, window_start, used) VALUES ('rdap', 'manual', ?, 1)", (stamp,))
    db_conn.commit()

    facts = asyncio.run(rdap.run("example.com", ctx))

    assert http.calls == 0
    assert [(f.type, f.status, f.error) for f in facts] == [
        ("created_at", "error", "budget"),
        ("registrar", "error", "budget"),
    ]
    from scamshield.web.view import _fact_line

    rows = [
        _fact_line(
            {
                "id": 1,
                "type": f.type,
                "source": f.source,
                "fetched_at": f.fetched_at,
                "data_mode": "LIVE",
                "status": f.status,
                "error": f.error,
                "value": {},
            },
            {},
            datetime.now(UTC),
        )
        for f in facts
    ]
    assert rows[0]["text"] == "Not checked: domain registry — request budget used"


def test_remaining_has_contract_shape(tmp_path):
    db.init(str(tmp_path / "scamshield.db"))
    budget = runtime.DbBudget(_settings(SourceCfg("enrich", budget_per_hour=3, extra={"reserve_manual": 2})))
    asyncio.run(budget.take("rdap", "manual"))

    left = asyncio.run(budget.remaining("rdap"))

    assert (left["manual"], left["auto"]) == (1, 1)
    assert left["resets_at"].endswith(":00:00Z")


def test_every_failure_reason_has_human_text():
    for reason in ("budget", "timeout", "unreachable", "http_429", "http_5xx", "disabled", "not_found", "bad_payload"):
        text = sources.not_checked_text("rdap", reason)
        assert text.startswith("Not checked: rdap — ") and text != f"Not checked: rdap — {reason}"  # not the raw code
