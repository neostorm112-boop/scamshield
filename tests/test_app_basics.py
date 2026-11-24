import sqlite3

import pytest
from fastapi.testclient import TestClient

from scamshield import config, db
from scamshield.contracts import Settings


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    return tmp_path


def test_configs_load_and_validate(data_dir):
    s = config.load()
    assert isinstance(s, Settings)
    ids = {b.id for b in s.brands}
    assert {"rta", "salik", "tamm", "aramex", "darb"} <= ids
    assert all(b.official_domains and b.keywords for b in s.brands)
    assert s.sources["ct_tiled"].extra["poll_seconds"] == 1
    assert len(s.sources["ct_tiled"].extra["logs"]) == 4
    assert s.scoring["rule_version"] == "v2-points"
    assert set(s.shared_infra) >= {"asns", "ns_suffixes", "cidrs"}
    assert s.db_path == str(data_dir / "scamshield.db")


def test_config_rejects_brand_without_domains(tmp_path):
    bad = tmp_path / "brands.yaml"
    bad.write_text("- id: x\n  name: X\n  official_domains: []\n  keywords: [x]\n")
    with pytest.raises(ValueError):
        config.load_brands(bad)


def test_schema_creates_and_is_idempotent(data_dir):
    s = config.load()
    db.init(s.db_path)
    first = _tables(s.db_path)
    db.init(s.db_path)
    assert _tables(s.db_path) == first
    assert {"domains", "facts", "jobs", "edges", "feedback", "budgets"} <= first
    mode = sqlite3.connect(s.db_path).execute("PRAGMA journal_mode").fetchone()[0]
    assert mode == "wal"


def _tables(path):
    rows = sqlite3.connect(path).execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {r[0] for r in rows}


def test_sqlite_version_check():
    db.check_sqlite_version((3, 35, 0))
    with pytest.raises(RuntimeError):
        db.check_sqlite_version((3, 34, 1))


def test_feed_page_is_empty_and_ok(data_dir):
    from scamshield.app import create_app

    with TestClient(create_app()) as c:
        r = c.get("/")
    assert r.status_code == 200
    assert "ScamShield" in r.text
    assert "Paste a link to check" in r.text and "Nothing to check right now." in r.text


def test_lifespan_starts_one_ct_task_per_configured_log(data_dir, monkeypatch):
    import asyncio

    from scamshield import app as app_module

    started = []

    async def monitor(log, settings, http):
        started.append(log)
        await asyncio.Event().wait()

    async def resolve(ctx, previous=None):
        return ctx.settings.sources["ct_tiled"].extra["logs"]

    monkeypatch.setattr(app_module, "monitor_ct_log", monitor)
    monkeypatch.setattr(app_module.ct_tiled, "resolve_logs", resolve)
    with TestClient(app_module.create_app()) as c:
        c.get("/")

    assert len(started) == 4


def test_ct_manager_stops_readers_of_logs_that_left_the_list(data_dir, monkeypatch):
    import asyncio

    from scamshield import app as app_module
    from scamshield.config import load

    lists = iter([["a/2026h2", "b/2027h1"], ["b/2027h1"]])

    async def monitor(log, settings, http):
        await asyncio.Event().wait()

    async def resolve(ctx, previous=None):
        return next(lists)

    async def sleep(_):
        if "second" in tasks_seen:
            raise StopAsyncIteration
        tasks_seen.append("second")

    tasks_seen, tasks = [], {}
    monkeypatch.setattr(app_module, "monitor_ct_log", monitor)
    monkeypatch.setattr(app_module.ct_tiled, "resolve_logs", resolve)
    monkeypatch.setattr(app_module.asyncio, "sleep", sleep)

    async def go():
        try:
            await app_module.monitor_ct_logs(load(), None, tasks)
        except StopAsyncIteration:
            pass

    asyncio.run(go())
    assert list(tasks) == ["b/2027h1"]


def _strip(client):
    """Source entries the header banner shows (its title and status dot), read like /partials/banner reads them."""
    from scamshield import db
    from scamshield.web import routes

    return routes._all_sources(client.app.state.settings, __import__("asyncio").run(db.run(routes._source_rows)))


def test_source_strip_lists_configured_ct_logs(data_dir, monkeypatch):
    from scamshield import app as app_module

    async def monitor(log, settings, http):
        await __import__("asyncio").Event().wait()

    monkeypatch.setattr(app_module, "monitor_ct_log", monitor)
    with TestClient(app_module.create_app()) as c:
        names = " ".join(s["name"] for s in _strip(c))

    assert "CT Willow" in names
    assert "CT Sycamore" in names


def test_source_strip_shows_last_ct_cycle_result(data_dir, monkeypatch):
    from scamshield import app as app_module
    from scamshield import db

    async def monitor(log, settings, http):
        await __import__("asyncio").Event().wait()

    def record(conn):
        conn.execute(
            "INSERT INTO sources (name, kind, data_mode, status, last_success_at, calls_today) VALUES ('ct_tiled:https://mon.willow.ct.letsencrypt.org/2026h2', 'connector', 'LIVE', 'ok', '2026-11-19T08:00:00Z', 12)"
        )
        conn.commit()

    monkeypatch.setattr(app_module, "monitor_ct_log", monitor)
    with TestClient(app_module.create_app()) as c:
        __import__("asyncio").run(db.run(record))
        statuses = " ".join(s["status"] for s in _strip(c))

    assert "12 records" in statuses
    assert "2026-11-19T08:00:00Z" in statuses


def test_feed_loads_local_htmx_for_source_polling(data_dir, monkeypatch):
    from scamshield import app as app_module

    async def monitor(log, settings, http):
        await __import__("asyncio").Event().wait()

    monkeypatch.setattr(app_module, "monitor_ct_log", monitor)
    with TestClient(app_module.create_app()) as c:
        page = c.get("/")
        script = c.get("/static/htmx.min.js")

    assert 'src="/static/htmx.min.js"' in page.text
    assert script.status_code == 200
    assert "htmx" in script.text


def test_feed_shows_discovered_ct_domain(data_dir, monkeypatch):
    from scamshield import app as app_module
    from scamshield import db

    async def monitor(log, settings, http):
        await __import__("asyncio").Event().wait()

    def insert_domain(conn):
        conn.execute("""INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, data_mode)
                     VALUES ('e1isalat-pay.com', 'e1isalat-pay.com', '2026-11-19T08:00:00Z', 'ct_tiled', 'LIVE')""")
        conn.commit()

    monkeypatch.setattr(app_module, "monitor_ct_log", monitor)
    with TestClient(app_module.create_app()) as c:
        __import__("asyncio").run(db.run(insert_domain))
        response = c.get("/")

    assert "e1isalat-pay.com" in response.text
    assert "cert log" in response.text


def test_supervise_restarts_crashed_loop_and_records_error(data_dir):
    import asyncio
    import sqlite3

    from scamshield import app as app_module
    from scamshield import config, db

    db.init(config.load().db_path)
    calls = []

    async def loop():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")

    asyncio.run(app_module.supervise("worker", loop, 1))

    assert len(calls) == 2
    row = sqlite3.connect(config.load().db_path).execute("SELECT status FROM sources WHERE name='worker'").fetchone()
    assert row[0].startswith("error: RuntimeError")


def test_supervise_survives_when_the_error_cannot_be_recorded(data_dir, monkeypatch):
    """A locked database while recording the crash must not kill the supervisor (the worker then never came back)."""
    import asyncio
    import sqlite3

    from scamshield import app as app_module
    from scamshield import config, db

    db.init(config.load().db_path)
    calls = []

    def locked(conn, name, error):
        raise sqlite3.OperationalError("database is locked")

    async def loop():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")

    monkeypatch.setattr(app_module, "_record_source_error", locked)
    asyncio.run(app_module.supervise("worker", loop, 1))
    assert len(calls) == 2


def test_run_worker_cancels_sibling_loops_when_one_crashes(data_dir, monkeypatch):
    """One crashed loop must stop the others before supervise restarts the set (no duplicate loops, no double-processing)."""
    import asyncio

    from scamshield import app as app_module
    from scamshield import config, db, worker

    db.init(config.load().db_path)
    settings = config.load()
    started, cancelled = [], []

    async def process_next(settings, http):
        n = len(started)
        started.append(n)
        if n == 0:
            await asyncio.sleep(0.05)
            raise RuntimeError("boom")
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.append(n)
            raise
        return False

    monkeypatch.setattr(worker, "process_next", process_next)

    async def main():
        try:
            await asyncio.wait_for(app_module.run_worker(settings, None), 2)
        except Exception as exc:  # noqa: BLE001
            return exc, sorted(cancelled)  # siblings must already be stopped when the crash reaches supervise

    exc, stopped = asyncio.run(main())
    assert exc is not None and not isinstance(exc, TimeoutError)
    assert stopped == list(range(1, settings.sources["worker"].extra["concurrency"]))
