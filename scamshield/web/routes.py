from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from urllib.parse import parse_qs

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse

from scamshield import (
    db,
    explain,
    feedback,
    intake,
    live,
    netsafe,
    runtime,
    snapshot,
    takedown,
    worker,
)
from scamshield import sources as source_text
from scamshield.connectors import tavily_search, urlscan_relatives
from scamshield.contracts import NormalizedURL
from scamshield.web import view

router = APIRouter()


def _source_rows(conn):
    rows = {row["name"]: dict(row) for row in conn.execute("SELECT * FROM sources")}
    for row in conn.execute("SELECT key, value FROM feed_meta WHERE key LIKE 'ct:%'"):
        rows.setdefault(f"ct_tiled:{row['key'][3:]}", {})["stats"] = json.loads(row["value"])
    active = conn.execute("SELECT value FROM feed_meta WHERE key = 'ct_logs'").fetchone()
    if active:
        rows["ct_logs"] = json.loads(active["value"])
    return rows


RED_AFTER_DOWN_S = 600  # ERRORS.md: CT log down 10 min -> red
SKIP_AMBER_S = 3600


def _ct_sources(settings, rows, now=None) -> list[dict]:
    """One strip entry per CT log: state ok/amber/red by ERRORS.md, rate (entries/s), lag in entries and minutes."""
    now = now or time.time()
    cfg = settings.sources["ct_tiled"].extra
    result = []
    for log in rows.get("ct_logs") or cfg["logs"]:
        row = rows.get(f"ct_tiled:{log}", {})
        stats = row.get("stats", {})
        samples = stats.get("samples", [])
        rate = (
            round((samples[-1][1] - samples[0][1]) / (samples[-1][0] - samples[0][0]), 1)
            if len(samples) > 1 and samples[-1][0] > samples[0][0]
            else None
        )
        skipped = stats.get("skipped")
        if row.get("status", "ok").startswith("error"):
            state = "red" if now - stats.get("down_since", now) >= RED_AFTER_DOWN_S else "amber"
            status = source_text.status_text(row["status"])
        elif skipped and now - skipped["at"] < SKIP_AMBER_S:
            state = "amber"
            status = f"skipped entries {skipped['from']}–{skipped['to']} (≈ {skipped['from_ts'][11:16]}–{skipped['to_ts'][11:16]}) to catch up"
        elif stats.get("lag_minutes", 0) > cfg["amber_lag_minutes"]:
            state, status = "amber", "catching up"
        else:
            state = "ok"
            status = (
                f"{row['calls_today']} records · {row['last_success_at']}"
                if row.get("last_success_at")
                else "monitoring"
            )
        result.append(
            {
                "name": f"CT {log.split('//')[1].split('.')[1].title()} {log.rsplit('/', 1)[-1]}",
                "status": status,
                "state": state,
                "rate": rate,
                "lag_entries": stats.get("lag_entries"),
                "lag_minutes": stats.get("lag_minutes"),
            }
        )
    return result


def _feed_sources(settings, rows, now=None) -> list[dict]:
    """One strip entry per phishing list; failed or older than stale_hours -> amber "last update HH:MM (stale)" (ERRORS.md)."""
    now = now or datetime.now(UTC)
    cfg = settings.sources["feeds"].extra
    result = []
    for name in cfg["urls"]:
        row = rows.get(f"feeds:{name}")
        last = row.get("last_success_at") if row else None
        if row is None:
            state, status = "grey", "not loaded yet"
        elif row["status"] != "ok" or (
            last and (now - datetime.fromisoformat(last)).total_seconds() > cfg["stale_hours"] * 3600
        ):
            state, status = "amber", f"last update {last[11:16] if last else 'never'} (stale)"
        else:
            state, status = "ok", f"updated {last[11:16]}"
        result.append(
            {"name": name, "status": status, "state": state, "rate": None, "lag_entries": None, "lag_minutes": None}
        )
    return result


def _search_source(rows) -> dict:
    """Strip entry for web search; on failure ERRORS.md wording, plus the time of the last results we still show."""
    row = rows.get("tavily")
    if row is None:
        return {
            "name": "web search",
            "status": "not run yet",
            "state": "grey",
            "rate": None,
            "lag_entries": None,
            "lag_minutes": None,
        }
    last = row.get("last_success_at")
    if row["status"] == "ok":
        state, status = "ok", f"searched {last[11:16]}" if last else "ok"
    else:
        state, status = (
            "amber",
            source_text.not_checked_text("web search", row["last_error"])
            + (f" · results cached at {last[11:16]}" if last else ""),
        )
    return {
        "name": "web search",
        "status": status,
        "state": state,
        "rate": None,
        "lag_entries": None,
        "lag_minutes": None,
    }


def _pull_source(rows, name: str, label: str) -> dict:
    """Strip entry for a key-based source: no key is a quiet grey "off - no key", failures use the ERRORS.md wording."""
    row = rows.get(name)
    entry = {"name": label, "rate": None, "lag_entries": None, "lag_minutes": None}
    last = row.get("last_success_at") if row else None
    if row is None:
        return {**entry, "status": "not run yet", "state": "grey"}
    if row["status"] == "off":
        return {**entry, "status": "off — no key", "state": "grey"}
    if row["status"] == "ok":
        return {**entry, "status": f"updated {last[11:16]}", "state": "ok"}
    return {
        **entry,
        "status": source_text.not_checked_text(label, row["last_error"])
        + (f" · last update {last[11:16]}" if last else ""),
        "state": "amber",
    }


def _check_state(conn, fqdn: str, now: str | None = None) -> dict:
    """Poll flag and status line from the domain's latest check_domain job."""
    job = conn.execute(
        "SELECT status, run_after, error FROM jobs WHERE kind = 'check_domain' AND target = ? ORDER BY id DESC LIMIT 1",
        (fqdn,),
    ).fetchone()
    if job is None or job["status"] in ("done", "partial"):
        return {"poll": False, "text": None}
    if job["status"] == "failed":
        return {"poll": False, "text": f"Check failed: {source_text.reason_text(job['error'])}"}
    now = now or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if job["status"] == "queued" and job["run_after"] and job["run_after"] > now:
        return {"poll": True, "text": f"Retrying at {job['run_after'][11:16]}"}
    return {"poll": True, "text": "Checking…"}


def _view_key(decided=0, filtered=0, low=0, baseline=0) -> str:
    """The one list the queue shows; the URL flags are exclusive, the first one set wins."""
    return "decided" if decided else "filtered" if filtered else "low" if low else "baseline" if baseline else "todo"


def _workspace_data(conn, settings, fqdn, from_, key, shown):
    q = view.queue(conn, settings, open_fqdn=fqdn, from_=from_)
    name = fqdn or (q["todo"][0]["fqdn"] if q["todo"] else None)
    case = view.load_case(conn, settings, name) if name else None
    modes = {r["data_mode"] for r in q["todo"]} | ({case["domain"]["data_mode"]} if case else set())
    return {
        "q": q,
        "v": view.pick(q, key, shown),
        "case": case,
        "open": name,
        "next": view.next_after(q["todo"], name),
        "last_saved": view.last_saved(conn),
        "monitor": view.monitor_time(conn),
        "ws_last": view.search_last_run(conn),
        "baseline_n": conn.execute("SELECT count(*) FROM domains WHERE found_by = 'baseline'").fetchone()[0],
        "demo": "DEMO" in modes,
    }


async def workspace(
    request: Request,
    fqdn: str | None = None,
    *,
    from_: str | None = None,
    decided=0,
    filtered=0,
    low=0,
    baseline=0,
    rows=0,
    change=0,
    error=None,
    since=None,
):
    key = _view_key(decided, filtered, low, baseline)
    data = await db.run(_workspace_data, request.app.state.settings, fqdn, from_, key, rows)
    missing = bool(fqdn) and data["case"] is None
    context = {
        **data,
        "fqdn": fqdn,
        "from_": from_,
        "view_key": key,
        "change": bool(change),
        "error": error,
        "missing": missing,
        "since": since or live.iso(datetime.now(UTC)),
    }
    return request.app.state.templates.TemplateResponse(
        request, "index.html", context, status_code=404 if missing else 200
    )


@router.get("/")
async def home(request: Request, decided: int = 0, filtered: int = 0, low: int = 0, baseline: int = 0, rows: str = ""):
    return await workspace(request, None, decided=decided, filtered=filtered, low=low, baseline=baseline, rows=rows)


@router.get("/partials/feed-rows")
async def feed_rows(
    request: Request,
    since: str,
    d: str = "",
    from_: str = Query("", alias="from"),
    decided: int = 0,
    filtered: int = 0,
    low: int = 0,
    baseline: int = 0,
    rows: str = "",
):
    """Queue rows of the open view for the 5 s poll; rows read by us after `since` (page load time) carry the blue "new" dot."""
    data = await db.run(
        lambda conn: view.queue(conn, request.app.state.settings, open_fqdn=d or None, from_=from_ or None)
    )
    v = view.pick(data, _view_key(decided, filtered, low, baseline), rows)
    moment = live.parse_ts(since)
    for row in v["rows"]:
        read = live.parse_ts(row["ingested_at"])
        row["new"] = bool(moment and read and read > moment)
    return request.app.state.templates.TemplateResponse(
        request, "_queue.html", {"q": data, "v": v, "open": d, "from_": from_, "since": since, "oob": True}
    )


@router.post("/check")
async def check(request: Request):
    values = parse_qs((await request.body()).decode("utf-8"))
    result = await netsafe.check_url(values.get("url", [""])[0])
    if not isinstance(result, NormalizedURL):
        return await workspace(request, None, error=result.message)
    await intake.submit(result.fqdn, "manual", [], 10)
    return RedirectResponse(f"/d/{result.fqdn}?from=paste", status_code=303)


@router.post("/search/run")
async def search_run(request: Request):
    await tavily_search.run_once(runtime.make_ctx(request.app.state.settings, request.app.state.http, "manual"))
    return RedirectResponse("/", status_code=303)


@router.get("/d/{fqdn}")
async def card(
    request: Request,
    fqdn: str,
    from_: str = Query("", alias="from"),
    decided: int = 0,
    filtered: int = 0,
    low: int = 0,
    baseline: int = 0,
    rows: str = "",
    change: int = 0,
):
    await explain.on_open(
        fqdn.lower()
    )  # the AI explanation starts by itself when the card is opened (never raises, never waits)
    return await workspace(
        request,
        fqdn.lower(),
        from_=from_ or None,
        decided=decided,
        filtered=filtered,
        low=low,
        baseline=baseline,
        rows=rows,
        change=change,
    )


@router.get("/d/{fqdn}/partials/facts")
async def facts(request: Request, fqdn: str, from_: str = Query("", alias="from")):
    """The polled part of a case (steps 1-3) while its check runs; when the check is over, tell htmx to reload the whole page so step 4 and the queue match."""
    case = await db.run(view.load_case, request.app.state.settings, fqdn.lower())
    if case is None:
        raise HTTPException(status_code=404)
    response = request.app.state.templates.TemplateResponse(
        request, "_case_body.html", {"case": case, "fqdn": fqdn.lower(), "from_": from_}
    )
    if case and not case["check"]["poll"]:
        response.headers["HX-Redirect"] = f"/d/{fqdn.lower()}" + (f"?from={from_}" if from_ else "")
    return response


@router.post("/d/{fqdn}/feedback")
async def save_feedback(request: Request, fqdn: str):
    def domain_id(conn):
        row = conn.execute("SELECT id FROM domains WHERE fqdn = ?", (fqdn.lower(),)).fetchone()
        return row["id"] if row else None

    values = parse_qs((await request.body()).decode("utf-8"))
    target = await db.run(domain_id)
    if target is None or not await feedback.save(
        target, values.get("verdict", [""])[0], values.get("reason", [""])[0], None
    ):
        return RedirectResponse(f"/d/{fqdn}", status_code=303)
    if values["verdict"][0] == "scam":
        await db.run(worker.recheck_neighbours, fqdn.lower(), request.app.state.settings)
    todo = (await db.run(view.queue, request.app.state.settings))["todo"]
    promised = values.get("next", [""])[0]  # ④ promised this case: open exactly it unless it was decided meanwhile
    names = [r["fqdn"] for r in todo if r["tier"] != 4]
    following = promised if promised in names else (names[0] if names else None)
    return RedirectResponse(f"/d/{following}" if following else "/", status_code=303)


@router.get("/d/{fqdn}/partials/explanation")
async def explanation(request: Request, fqdn: str):
    """The AI explanation block, polled every 3 s while the AI writes it; starts it if the card has none yet (no button)."""
    await explain.on_open(fqdn.lower())
    state = await db.run(explain.card_state, fqdn.lower())
    return request.app.state.templates.TemplateResponse(
        request,
        "_explanation.html",
        {"case": {"explanation": state, "check": {"poll": False}}, "fqdn": fqdn.lower(), "oob": True},
    )


@router.post("/d/{fqdn}/snapshot")
async def take_snapshot(request: Request, fqdn: str):
    """Analyst click: the browser runs now (up to 25 s) and the case reloads with the picture or the reason it was not taken."""
    await snapshot.take(request.app.state.settings, fqdn.lower())
    return RedirectResponse(f"/d/{fqdn.lower()}", status_code=303)


@router.post("/d/{fqdn}/relatives")
async def find_relatives(request: Request, fqdn: str):
    """Analyst click: up to 3 urlscan searches for sites sharing this one's script, panel or IP; found sites are queued, never marked scam."""
    await urlscan_relatives.find(
        runtime.make_ctx(request.app.state.settings, request.app.state.http, "manual"), fqdn.lower()
    )
    return RedirectResponse(f"/d/{fqdn.lower()}", status_code=303)


def _takedown_text(conn, settings, fqdn: str) -> str | None:
    case = view.load_case(conn, settings, fqdn)
    if case is None:
        return None
    facts = [{**dict(f), "value": json.loads(f["value_json"])} for f in db.current_facts(conn, case["domain"]["id"])]
    shots = [
        r["captured_at"]
        for r in conn.execute(
            "SELECT captured_at FROM artifacts WHERE domain_id = ? AND kind = 'screenshot' ORDER BY id",
            (case["domain"]["id"],),
        )
    ]
    return takedown.build(case, facts, shots, {b.id: b for b in settings.brands})


@router.get("/d/{fqdn}/takedown")
async def takedown_page(request: Request, fqdn: str):
    text = await db.run(_takedown_text, request.app.state.settings, fqdn.lower())
    if text is None:
        return await workspace(request, fqdn.lower())
    return request.app.state.templates.TemplateResponse(request, "takedown.html", {"fqdn": fqdn.lower(), "text": text})


@router.get("/d/{fqdn}/takedown.txt")
async def takedown_text(request: Request, fqdn: str):
    text = await db.run(_takedown_text, request.app.state.settings, fqdn.lower())
    if text is None:
        return await workspace(request, fqdn.lower())
    return PlainTextResponse(text)


@router.get("/evidence/{artifact_id}")
async def evidence(artifact_id: int):
    """Only the PNG of a stored screenshot, by id: no path from the request, never HTML."""
    row = await db.run(
        lambda conn: conn.execute(
            "SELECT path FROM artifacts WHERE id = ? AND kind = 'screenshot'", (artifact_id,)
        ).fetchone()
    )
    if not row:
        raise HTTPException(404)
    return FileResponse(
        row["path"],
        media_type="image/png",
        headers={"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'"},
    )


@router.post("/d/{fqdn}/restore")
async def restore(fqdn: str):
    """Return a filtered-out (NOISE) domain to the queue: an "unclear" verdict is a guard, so the next assessment never hides it again."""

    def run(conn):
        row = conn.execute("SELECT id, state FROM domains WHERE fqdn = ?", (fqdn.lower(),)).fetchone()
        if row and row["state"] == "NOISE":
            conn.execute("UPDATE domains SET state = 'REVIEW' WHERE id = ?", (row["id"],))
            conn.commit()
            return row["id"]
        return None

    target = await db.run(run)
    if target:
        await feedback.save(target, "unclear", "restored: returned to queue from filtered out", None)
    return RedirectResponse(f"/d/{fqdn}", status_code=303)


def _all_sources(settings, rows) -> list[dict]:
    return [
        *_ct_sources(settings, rows),
        *_feed_sources(settings, rows),
        _search_source(rows),
        _pull_source(rows, "urlhaus", "URLhaus"),
        _pull_source(rows, "urlscan", "urlscan"),
        _pull_source(rows, "nrd", "new domains (smet.cz)"),
    ]


@router.get("/healthz")
async def healthz():
    return await db.run(live.health)


@router.get("/partials/banner")
async def banner(request: Request):
    rows = await db.run(_source_rows)
    return request.app.state.templates.TemplateResponse(
        request,
        "_banner.html",
        {
            "h": await db.run(live.health),
            "sources": _all_sources(request.app.state.settings, rows),
            "ai_paused": await db.run(explain.paused),
        },
    )
