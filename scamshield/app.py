"""FastAPI app: lifespan applies the schema and starts the background loops (connectors, feeds, worker, snapshots); routes live in scamshield/web."""

from __future__ import annotations

import asyncio
import json
import re
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape
from starlette.middleware.trustedhost import TrustedHostMiddleware

from scamshield import config, db, live, runtime, snapshot, sources, triage_ai, worker
from scamshield.connectors import ct_tiled, feeds, nrd, tavily_search, urlhaus, urlscan
from scamshield.web.routes import router

templates = Jinja2Templates(directory=Path(__file__).with_name("web") / "templates")
templates.env.globals["not_checked"] = sources.not_checked_text

# The tool listens on localhost only; any other Host (DNS rebinding) or Origin (a web page posting to us) is foreign.
LOCAL_HOSTS = ["127.0.0.1", "localhost", "[::1]", "::1", "testserver"]  # testserver: Starlette TestClient


def gst(iso: str | None, now: datetime | None = None) -> str:
    """UTC ISO timestamp -> 'HH:MM GST' (UTC+4), with the date when it is not today in GST. Stored facts stay UTC."""
    if not iso:
        return ""
    try:
        moment = datetime.fromisoformat(iso).astimezone(timezone(timedelta(hours=4)))
    except ValueError:
        return iso
    today = (now or datetime.now(UTC)).astimezone(moment.tzinfo).date()
    return moment.strftime("%H:%M GST" if moment.date() == today else "%Y-%m-%d %H:%M GST")


templates.env.filters["gst"] = gst
templates.env.filters["wbr_dots"] = lambda text: Markup(
    str(escape(text)).replace(".", ".<wbr>")
)  # escape first, then add the break hints
templates.env.filters["strip_eids"] = lambda text: re.sub(
    r"\s*\((?:E\d+(?:,\s*)?)+\)", "", text
)  # the model cites evidence ids; the plain-words AI block does not show them


def _cursor(conn, connector):
    row = conn.execute("SELECT cursor FROM cursors WHERE connector = ?", (connector,)).fetchone()
    return row["cursor"] if row else None


def _record_source_error(conn, name, error):
    conn.execute(
        """INSERT INTO sources (name, kind, data_mode, status, last_error, last_error_at)
                 VALUES (?, 'connector', 'LIVE', ?, ?, datetime('now'))
                 ON CONFLICT(name) DO UPDATE SET status=excluded.status, last_error=excluded.last_error,
                 last_error_at=excluded.last_error_at""",
        (name, f"error: {error}", error),
    )
    conn.commit()


def _record_ct_cycle(conn, log, result, now=None):
    """Save the source row plus feed_meta "ct:<log>" stats (rate samples, lag, skip, down_since) for the strip."""
    now = now or time.time()
    key = f"ct:{log}"
    row = conn.execute("SELECT value FROM feed_meta WHERE key = ?", (key,)).fetchone()
    stats = json.loads(row["value"]) if row else {}
    if result["status"] != "ok":
        stats.setdefault("down_since", now)
    else:
        cursor = int(result["cursor"])
        stats.pop("down_since", None)
        if "skipped" in result:
            stats["skipped"] = {**result["skipped"], "at": now}
            stats["samples"] = []  # a jump is not reading speed
        stats["samples"] = [*stats.get("samples", []), [now, cursor]][-6:]
        stats["lag_entries"] = max((result.get("size") or cursor) - cursor, 0)
        last_ts = result.get("last_ts")
        stats["lag_minutes"] = (
            round((now - datetime.fromisoformat(last_ts).timestamp()) / 60, 1)
            if stats["lag_entries"] and last_ts
            else 0
        )
    conn.execute(
        "INSERT INTO feed_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, json.dumps(stats)),
    )
    if result["status"] != "ok":
        return _record_source_error(conn, f"ct_tiled:{log}", result.get("error") or result["status"])
    conn.execute(
        """INSERT INTO sources (name, kind, data_mode, status, last_success_at, calls_today)
                 VALUES (?, 'connector', 'LIVE', 'ok', datetime('now'), ?)
                 ON CONFLICT(name) DO UPDATE SET status=excluded.status, last_success_at=excluded.last_success_at,
                 calls_today=sources.calls_today + excluded.calls_today""",
        (f"ct_tiled:{log}", result["records"]),
    )
    conn.commit()


async def supervise(name: str, coro_factory, backoff_max_s: float) -> None:
    """Restart a crashed background loop with exponential backoff, recording the error as the source status."""
    delay = 1.0
    while True:
        try:
            return await coro_factory()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - any crash must restart the loop
            try:
                await db.run(_record_source_error, name, f"{type(exc).__name__}: {exc}")
            except Exception:  # noqa: BLE001 - a busy database must not kill the supervisor (worker never came back)
                print(f"{name} crashed ({type(exc).__name__}: {exc}); status not recorded, database busy", flush=True)
            await asyncio.sleep(delay)
            delay = min(delay * 2, backoff_max_s)


async def monitor_ct_log(log: str, settings, http) -> None:
    """Run one bounded CT poll per configured interval; cancellation is handled by lifespan."""
    cfg = settings.sources["ct_tiled"]
    ctx = runtime.make_ctx(settings, http, "auto")
    while True:
        cursor = await db.run(_cursor, log)
        result = await ct_tiled.run_once(log, cursor, ctx)
        await db.run(_record_ct_cycle, log, result)
        await db.run(live.ct_beat, log, cursor, result)
        await asyncio.sleep(max(cfg.extra["poll_seconds"], result.get("retry_after_s", 0)))


async def monitor_ct_logs(settings, http, tasks: dict) -> None:
    """Keep one supervised reader per selected log; shards that appear later are started from their tail, shards that left the list are stopped."""
    cfg = settings.sources["ct_tiled"].extra
    ctx = runtime.make_ctx(settings, http, "auto")
    logs = None
    while True:
        logs = await ct_tiled.resolve_logs(ctx, logs)
        await db.run(_save_ct_logs, logs)
        for log in logs:
            if log not in tasks:
                tasks[log] = asyncio.create_task(
                    supervise(
                        f"ct_tiled:{log}", lambda log=log: monitor_ct_log(log, settings, http), cfg["backoff_max_s"]
                    )
                )
        for log in [log for log in tasks if log not in logs]:
            tasks.pop(log).cancel()
        await asyncio.sleep(cfg["log_list_refresh_hours"] * 3600)


def _save_ct_logs(conn, logs):
    conn.execute(
        "INSERT INTO feed_meta (key, value) VALUES ('ct_logs', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (json.dumps(logs),),
    )
    conn.commit()


def _feeds_beat(conn, failed: dict, total: int):
    live.beat(conn, "feeds", len(failed) < total, error=json.dumps(failed) if failed else None)


def _feeds_age_s(conn):
    """Seconds since the newest successful list download, None if there was none."""
    times = [
        live.parse_ts(json.loads(row["value"]).get("fetched_at"))
        for row in conn.execute("SELECT value FROM feed_meta WHERE key LIKE 'feed:%'")
    ]
    times = [t for t in times if t]
    return (datetime.now(UTC) - max(times)).total_seconds() if times else None


async def monitor_feeds(settings, http) -> None:
    """Refresh the phishing lists every refresh_hours; after a failure retry once after retry_minutes."""
    cfg = settings.sources["feeds"].extra
    ctx = runtime.make_ctx(settings, http, "auto")
    retried = False
    first = True
    while True:
        age = await db.run(_feeds_age_s) if first else None
        first = False
        if age is not None and age < cfg["refresh_hours"] * 3600:  # restarts must not re-download 3 lists
            print(
                f"feeds: lists are {int(age // 60)} min old, refresh skipped", flush=True
            )  # stdout: no logging config in this app
            await db.run(lambda conn: live.beat(conn, "feeds", error="skipped: lists still fresh"))
            await asyncio.sleep(cfg["refresh_hours"] * 3600 - age)
            continue
        result = await feeds.run_once(ctx)
        await db.run(_feeds_beat, result["failed"], len(cfg["urls"]))
        retry = bool(result["failed"]) and not retried
        retried = retry
        await asyncio.sleep(cfg["retry_minutes"] * 60 if retry else cfg["refresh_hours"] * 3600)


async def monitor_dns(settings, http) -> None:
    """Look again at NXDOMAIN NOISE / GRAY_LOW domains every dns_watch_minutes; a domain that now resolves is re-assessed."""
    while True:
        await worker.recheck_resolving(settings, http)
        await asyncio.sleep(settings.sources["worker"].extra["dns_watch_minutes"] * 60)


async def monitor_search(settings, http) -> None:
    """Run every brand query each schedule_hours; the 24 h cache keeps repeats off the 40/day budget."""
    ctx = runtime.make_ctx(settings, http, "auto")
    while True:
        await tavily_search.run_once(ctx)
        await asyncio.sleep(settings.sources["tavily"].extra["schedule_hours"] * 3600)


def _pull_age_s(conn, name):
    """Seconds since the source last succeeded, None if it never did."""
    row = conn.execute("SELECT last_success_at FROM sources WHERE name = ?", (name,)).fetchone()
    when = live.parse_ts(row["last_success_at"]) if row else None
    return (datetime.now(UTC) - when).total_seconds() if when else None


async def monitor_pull(settings, http, name, run_once) -> None:
    """Pull a key-based source every refresh_hours; a restart inside that period waits instead of spending budget again."""
    period = settings.sources[name].extra["refresh_hours"] * 3600
    ctx = runtime.make_ctx(settings, http, "auto")
    while True:
        age = await db.run(_pull_age_s, name)
        if age is not None and age < period:
            await asyncio.sleep(period - age)
            continue
        await run_once(ctx)
        await asyncio.sleep(period)


async def monitor_snapshots(settings) -> None:
    """Snapshot queued GRAY / GRAY_LOW domains, up to `concurrency` at once (one Chromium process each), within the hourly budget in sources.yaml.
    Claims are made one at a time here; `auto_every_s` is only the wait when nothing can be claimed (queue empty or budget used up)."""
    cfg = settings.sources["snapshot"].extra
    slots, running, tasks = asyncio.Semaphore(cfg["concurrency"]), set(), set()
    try:
        while True:
            await slots.acquire()
            fqdn = None
            try:
                fqdn = await snapshot.claim_auto(settings, running)
            finally:
                if fqdn is None:
                    slots.release()
            if fqdn is None:
                await asyncio.sleep(cfg["auto_every_s"])
                continue
            task = asyncio.create_task(snapshot.run_claimed(settings, fqdn, running))
            tasks.add(task)
            task.add_done_callback(lambda t: (tasks.discard(t), slots.release()))
    finally:
        for task in tasks:
            task.cancel()


async def run_worker(settings, http) -> None:
    """`worker.concurrency` loops share the queue (checks wait on the network: one loop made ~8 checks/min: with the NRD feed one loop fell behind)."""
    await worker.recover_running_jobs()

    async def loop(beats: bool) -> None:
        last_beat = 0.0
        while True:
            if beats and time.time() - last_beat >= 60:  # wall clock on purpose: a sleeping laptop must show as a gap
                await db.run(live.beat, "worker")
                last_beat = time.time()
            if not await worker.process_next(settings, http):
                await asyncio.sleep(2)

    async with asyncio.TaskGroup() as group:  # one crashed loop cancels the others before supervise restarts the set
        for i in range(settings.sources["worker"].extra["concurrency"]):
            group.create_task(loop(i == 0))


def create_app(background: bool = True) -> FastAPI:
    """background=False skips CT monitors and the worker (tests that inspect queued state)."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = config.load()
        db.init(app.state.settings.db_path)
        for fqdn in await db.run(
            triage_ai.mark_interrupted
        ):  # a judge call cut by the last stop: judged again now (caps, one at a time)
            triage_ai.auto_in_background(fqdn)
        await db.run(live.beat, "boot")
        app.state.http = httpx.AsyncClient(
            headers={"Accept-Encoding": "gzip, identity"},
            limits=httpx.Limits(max_connections=app.state.settings.sources["ct_tiled"].extra["http_max_connections"]),
        )
        ct_cfg = app.state.settings.sources["ct_tiled"]
        app.state.ct_tasks = {}
        app.state.ct_manager = (
            asyncio.create_task(
                supervise(
                    "ct_log_list",
                    lambda: monitor_ct_logs(app.state.settings, app.state.http, app.state.ct_tasks),
                    ct_cfg.extra["backoff_max_s"],
                )
            )
            if ct_cfg.enabled and background
            else None
        )
        feeds_cfg = app.state.settings.sources["feeds"]
        app.state.feeds_task = (
            asyncio.create_task(
                supervise(
                    "feeds", lambda: monitor_feeds(app.state.settings, app.state.http), feeds_cfg.extra["backoff_max_s"]
                )
            )
            if feeds_cfg.enabled and background
            else None
        )
        search_cfg = app.state.settings.sources["tavily"]
        app.state.search_task = (
            asyncio.create_task(
                supervise(
                    "tavily",
                    lambda: monitor_search(app.state.settings, app.state.http),
                    app.state.settings.sources["worker"].extra["backoff_max_s"],
                )
            )
            if search_cfg.enabled and background
            else None
        )
        app.state.pull_tasks = [
            asyncio.create_task(
                supervise(
                    name,
                    lambda name=name, run_once=run_once: monitor_pull(
                        app.state.settings, app.state.http, name, run_once
                    ),
                    app.state.settings.sources["worker"].extra["backoff_max_s"],
                )
            )
            for name, run_once in (("urlhaus", urlhaus.run_once), ("urlscan", urlscan.run_once), ("nrd", nrd.run_once))
            if app.state.settings.sources[name].enabled and background
        ]
        app.state.dns_task = (
            asyncio.create_task(
                supervise(
                    "dns_watch",
                    lambda: monitor_dns(app.state.settings, app.state.http),
                    app.state.settings.sources["worker"].extra["backoff_max_s"],
                )
            )
            if background
            else None
        )
        snap_cfg = app.state.settings.sources["snapshot"]
        app.state.snapshot_task = (
            asyncio.create_task(
                supervise(
                    "snapshot",
                    lambda: monitor_snapshots(app.state.settings),
                    app.state.settings.sources["worker"].extra["backoff_max_s"],
                )
            )
            if snap_cfg.enabled and background
            else None
        )
        app.state.worker_task = (
            None
            if not background
            else asyncio.create_task(
                supervise(
                    "worker",
                    lambda: run_worker(app.state.settings, app.state.http),
                    app.state.settings.sources["worker"].extra["backoff_max_s"],
                )
            )
        )
        try:
            yield
        finally:
            tasks = [
                *app.state.ct_tasks.values(),
                *app.state.pull_tasks,
                *[
                    t
                    for t in (
                        app.state.ct_manager,
                        app.state.feeds_task,
                        app.state.search_task,
                        app.state.dns_task,
                        app.state.snapshot_task,
                        app.state.worker_task,
                    )
                    if t
                ],
            ]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            ct_tiled._reset_pool()  # brand-match worker processes
            await app.state.http.aclose()

    app = FastAPI(title="ScamShield", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=Path(__file__).with_name("web") / "static"), name="static")
    app.state.templates = templates
    app.include_router(router)

    @app.middleware("http")
    async def reject_cross_site_writes(request, call_next):
        origin = request.headers.get("origin")
        if (
            origin
            and request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and (urlsplit(origin).hostname or "") not in {h.strip("[]") for h in LOCAL_HOSTS}
        ):
            return PlainTextResponse("Cross-site request refused", status_code=403)
        return await call_next(request)

    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=LOCAL_HOSTS
    )  # added last = outermost: checked before anything else

    return app


app = create_app()
