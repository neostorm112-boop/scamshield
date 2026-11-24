"""Tail the optional names-tile extension of Static CT logs."""

from __future__ import annotations

import asyncio
import json
import logging
import multiprocessing
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from scamshield import intake, sources
from scamshield.connectors import ct_data
from scamshield.contracts import Candidate, CandidateBatch, Ctx
from scamshield.enrich.lookalike import (
    fact_value,
    generic_name,
    match,
    smishing_pattern,
)

log = logging.getLogger(__name__)


def _tile_path(index: int) -> str:
    groups = []
    while True:
        groups.append(f"{index % 1000:03d}")
        index //= 1000
        if not index:
            break
    groups.reverse()
    return "/".join([*(f"x{group}" for group in groups[:-1]), groups[-1]])


def _checkpoint_size(body: str) -> int | None:
    lines = body.splitlines()
    try:
        return int(lines[1])
    except (IndexError, ValueError):
        return None


def _timestamp(milliseconds: int | None, fallback: str) -> str:
    if milliseconds is None:
        return fallback
    return datetime.fromtimestamp(milliseconds / 1000, UTC).isoformat().replace("+00:00", "Z")


@dataclass
class _Step:
    batch: CandidateBatch
    size: int | None = None
    last_ts: str | None = None  # timestamp of the last entry read, for lag in minutes
    skipped: dict | None = None


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


_generic = {"hour": "", "taken": 0, "seen": set(), "dropped": 0, "reported": 0}
# Brandless candidates: one slot per registrable domain per hour (`seen` holds only taken ones, so it never outgrows the budget); over the budget a name
# is dropped and counted. `dropped` is cumulative and handed out once (_dropped_unreported), so several logs never report the same drop.
# The hour is the wall clock of processing, not the entry timestamp: catching up on old entries spends the current hour's budget.


def _generic_slot(ctx: Ctx, apex: str, state: dict | None = None, budget_key: str = "budget_per_hour") -> bool:
    """state/budget_key: a source with its own pool (nrd: a daily file of 300k+ names must not eat the CT hour in seconds)."""
    state = _generic if state is None else state
    hour = ctx.now()[:13]
    if state["hour"] != hour:
        state.update(hour=hour, taken=0, seen=set())
    if apex in state["seen"]:
        return False
    if state["taken"] >= ctx.settings.scoring["generic"][budget_key]:
        state["dropped"] += 1
        return False
    state["taken"] += 1
    state["seen"].add(apex)
    return True


def _dropped_unreported() -> int:
    count = _generic["dropped"] - _generic["reported"]
    _generic["reported"] = _generic["dropped"]
    return count


def _data_mode(ctx: Ctx, base: str) -> bool:
    """Logs on these hosts (Google's) do not serve the names extension: read their data tiles instead."""
    return urlsplit(base).hostname in ctx.settings.sources["ct_tiled"].extra.get("data_tile_hosts", [])


def _is_contact_host(ctx: Ctx, url: str) -> bool:
    host = urlsplit(url).hostname or ""
    return any(
        host == suffix or host.endswith("." + suffix)
        for suffix in ctx.settings.sources["ct_tiled"].extra.get("contact_host_suffixes", [])
    )


def _headers(ctx: Ctx, url: str) -> dict | None:
    """User-Agent with the contact email, only for the hosts whose operator requires it."""
    email = ctx.settings.secrets.get("CT_CONTACT_EMAIL")
    return {"User-Agent": f"ScamShield/1.0 (mailto:{email})"} if email and _is_contact_host(ctx, url) else None


def _classify(fqdn: str, brands: list, scoring: dict, host_suffixes: list[str]) -> tuple[str, dict] | None:
    """("brand", hit) for a brand or SMS-pattern hit, ("generic", hit) for a brandless suspicious name, else None. Pure: same name, same answer."""
    hit = match(fqdn, brands) or smishing_pattern(fqdn)
    if hit:
        return "brand", hit
    hit = generic_name(fqdn, scoring, host_suffixes)
    return ("generic", hit) if hit else None


_worker_args: tuple = ()


def _worker_init(brands: list, scoring: dict, host_suffixes: list[str]) -> None:
    global _worker_args
    _worker_args = (brands, scoring, host_suffixes)


def _worker_classify(fqdns: list[str]) -> list:
    return [_classify(fqdn, *_worker_args) for fqdn in fqdns]


_CACHE_MAX = 100_000  # names; certificate and precertificate repeat the same names within minutes
_matcher: dict = {"settings": None, "cache": {}, "pool": None, "off_until": 0.0}
# Brand matching (~0.4 ms/name) took a whole core and the event loop with it, so busy logs fell behind. With match_processes > 0 the names of a full
# tile go to that many worker processes; the cache (fqdn -> verdict) lives here, in the main process, and is tied to the settings object it was made for.


def _reset_pool() -> None:
    pool, _matcher["pool"] = _matcher["pool"], None
    if pool is not None:
        pool.shutdown(wait=False, cancel_futures=True)


def _pool(processes: int, args: tuple) -> ProcessPoolExecutor:
    if _matcher["pool"] is None:
        _matcher["pool"] = ProcessPoolExecutor(
            processes, mp_context=multiprocessing.get_context("spawn"), initializer=_worker_init, initargs=args
        )
    return _matcher["pool"]


async def _classify_names(ctx: Ctx, fqdns: list[str]) -> dict[str, tuple[str, dict] | None]:
    if _matcher["settings"] is not ctx.settings:  # new brands or scoring: old verdicts and workers are stale
        _reset_pool()
        _matcher.update(settings=ctx.settings, cache={})
    cache = _matcher["cache"]
    out = {fqdn: cache[fqdn] for fqdn in fqdns if fqdn in cache}
    misses = [fqdn for fqdn in dict.fromkeys(fqdns) if fqdn not in out]
    if not misses:
        return out
    args = (ctx.settings.brands, ctx.settings.scoring, ctx.settings.shared_infra.get("host_suffixes", []))
    cfg = ctx.settings.sources["ct_tiled"].extra
    processes = cfg.get("match_processes", 0)
    results = None
    if processes and len(misses) >= cfg.get("match_pool_min_names", 200) and time.monotonic() >= _matcher["off_until"]:
        size = -(-len(misses) // processes)
        try:
            pool = _pool(processes, args)
            loop = asyncio.get_running_loop()
            parts = await asyncio.gather(
                *(
                    loop.run_in_executor(pool, _worker_classify, misses[i : i + size])
                    for i in range(0, len(misses), size)
                )
            )
            results = [verdict for part in parts for verdict in part]
        except (
            RuntimeError,
            OSError,
        ) as exc:  # a dead worker (BrokenProcessPool), a pool shut down meanwhile, a spawn that failed: match here, rebuild the pool next time
            log.warning(
                "ct_tiled: match workers failed (%s), matching in the main process for %d s",
                type(exc).__name__,
                cfg.get("match_pool_retry_s", 600),
            )
            _reset_pool()
            _matcher["off_until"] = time.monotonic() + cfg.get(
                "match_pool_retry_s", 600
            )  # workers that cannot start must not be respawned for every tile
    if results is None:
        results = [_classify(fqdn, *args) for fqdn in misses]
    out.update(zip(misses, results, strict=True))
    if _matcher["settings"] is ctx.settings:
        if len(cache) + len(misses) > _CACHE_MAX:
            cache.clear()
        cache.update(zip(misses, results, strict=True))
    return out


async def _read_tile(ctx: Ctx, base: str, tile_start: int, width: int) -> str | sources.SourceError:
    suffix = "" if width == 256 else f".p/{width}"
    if _data_mode(ctx, base):
        limit = ctx.settings.sources["ct_tiled"].extra["data_tile_max_bytes"]
        body = await sources.fetch_bytes(
            ctx, "ct_tiled", f"{base}/tile/data/{_tile_path(tile_start // 256)}{suffix}", limit
        )
        if isinstance(body, sources.SourceError):
            return body
        text = await asyncio.to_thread(ct_data.to_lines, body, limit, width)
        return sources.SourceError("ct_tiled", "bad_payload") if text is None else text
    return await sources.fetch_text(
        ctx, "ct_tiled", f"{base}/tile/names/{_tile_path(tile_start // 256)}{suffix}", _headers(ctx, base)
    )


async def _step(
    cursor: str | None,
    limit: int,
    ctx: Ctx,
    log_url: str | None = None,
    size: int | None = None,
    tiles: dict | None = None,
) -> _Step:
    """Read one names tile, emitting only DNS names that match configured brands.

    size/tiles: a checkpoint size and full tiles already fetched by run_once, so one request round trip serves many tiles."""
    cfg = ctx.settings.sources["ct_tiled"].extra
    base = (log_url or cfg["logs"][0]).rstrip("/")
    if size is None:
        checkpoint = await sources.fetch_text(ctx, "ct_tiled", f"{base}/checkpoint", _headers(ctx, base))
        if isinstance(checkpoint, sources.SourceError):
            return _Step(CandidateBatch([], cursor, "error", checkpoint.reason))
        size = _checkpoint_size(checkpoint)
        if size is None:
            return _Step(CandidateBatch([], cursor, "error", "checkpoint_invalid"))
    if cursor is None or int(cursor) >= size:
        return _Step(CandidateBatch([], str(size), "ok"), size)
    next_entry = int(cursor)
    tile_start = (next_entry // 256) * 256
    width = min(256, size - tile_start)
    tile = (tiles or {}).get(tile_start)
    if tile is None:
        tile = await _read_tile(ctx, base, tile_start, width)
    if isinstance(tile, sources.SourceError) and width < 256 and tile.reason in ("http_403", "http_404"):
        # the partial tile is gone once the log fills it: re-read the checkpoint and take the full tile
        checkpoint = await sources.fetch_text(ctx, "ct_tiled", f"{base}/checkpoint", _headers(ctx, base))
        if isinstance(checkpoint, sources.SourceError):
            return _Step(CandidateBatch([], cursor, "error", checkpoint.reason))
        size = _checkpoint_size(checkpoint)
        if size is None:
            return _Step(CandidateBatch([], cursor, "error", "checkpoint_invalid"))
        if size - tile_start < 256:
            return _Step(CandidateBatch([], cursor, "ok"), size)  # still partial: next poll
        width = 256
        tile = await _read_tile(ctx, base, tile_start, width)
    if isinstance(tile, sources.SourceError):
        return _Step(CandidateBatch([], cursor, "error", tile.reason), size)
    lines = tile.splitlines()[next_entry - tile_start : next_entry - tile_start + limit]
    first_ms = None
    for entry in lines[:1]:
        try:
            first_ms = json.loads(entry).get("Timestamp")
        except (json.JSONDecodeError, AttributeError):
            pass
    max_lag = cfg["max_lag_minutes"] * 60
    if (
        first_ms is not None
        and (_parse_ts(ctx.now()) - _parse_ts(_timestamp(first_ms, ctx.now()))).total_seconds() > max_lag
    ):
        skipped = {"from": next_entry, "to": size, "from_ts": _timestamp(first_ms, ctx.now()), "to_ts": ctx.now()}
        return _Step(CandidateBatch([], str(size), "ok"), size, skipped=skipped)
    rows = []
    for entry in lines:
        try:
            row = json.loads(entry)
        except json.JSONDecodeError:
            continue
        rows.append((row, [name.lower().removeprefix("*.").rstrip(".") for name in row.get("DNS", [])]))
    verdicts = await _classify_names(ctx, [fqdn for _, fqdns in rows for fqdn in fqdns])
    candidates = []
    last_ts = None
    for row, fqdns in rows:
        if row.get("Timestamp") is not None:
            last_ts = _timestamp(row["Timestamp"], ctx.now())
        for fqdn in fqdns:
            verdict = verdicts[fqdn]
            if verdict is None:
                continue
            kind, brand = verdict
            if kind == "generic":
                if not _generic_slot(ctx, brand["apex"]):
                    continue  # the slot is stateful (per hour, per apex): decided here in order, never in the workers
                fqdn = brand["host"]  # www./api. dropped; the slot is per apex
            candidates.append(
                Candidate(
                    fqdn,
                    "ct_tiled",
                    _timestamp(row.get("Timestamp"), ctx.now()),
                    "LIVE",
                    {"log": base, **fact_value(brand)},
                )
            )
    return _Step(
        CandidateBatch(candidates, str(min(size, tile_start + width, next_entry + limit)), "ok"), size, last_ts
    )


LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"


def select_logs(log_list: dict, now: datetime, operators: list[str], days: int) -> list[str]:
    """Monitoring URLs of usable tiled logs by the allowed operators whose expiry interval overlaps now..now+days.

    Static CT logs are sharded by certificate expiry, so certificates issued today land in the shard covering today + their lifetime.
    """
    end = now + timedelta(days=days)
    found = []
    for operator in log_list.get("operators", []):
        if operator.get("name") not in operators:
            continue
        for log in operator.get("tiled_logs", []):
            interval = log.get("temporal_interval", {})
            try:
                start, stop = (datetime.fromisoformat(interval[key]) for key in ("start_inclusive", "end_exclusive"))
            except (KeyError, ValueError):
                continue
            if "usable" in log.get("state", {}) and start <= end and stop > now and log.get("monitoring_url"):
                found.append(log["monitoring_url"].rstrip("/"))
    return sorted(found)


async def resolve_logs(ctx: Ctx, previous: list[str] | None = None) -> list[str]:
    """Logs to read now: from the gstatic log list; on any failure the last good list, else the configured one."""
    cfg = ctx.settings.sources["ct_tiled"].extra
    payload = await sources.fetch_json(ctx, "ct_tiled", LOG_LIST_URL)
    if not isinstance(payload, dict):
        return previous or cfg["logs"]
    found = select_logs(payload, _parse_ts(ctx.now()), cfg["log_operators"], cfg["expiry_window_days"])
    if not ctx.settings.secrets.get("CT_CONTACT_EMAIL"):
        kept = [url for url in found if not _is_contact_host(ctx, url)]
        if len(kept) < len(found):
            log.warning("ct_tiled: %d log(s) skipped, they need CT_CONTACT_EMAIL (not set)", len(found) - len(kept))
        found = kept
    return found or previous or cfg["logs"]


async def fetch(
    cursor: str | None, since: str | None, limit: int, ctx: Ctx, log_url: str | None = None
) -> CandidateBatch:
    del since
    return (await _step(cursor, limit, ctx, log_url)).batch


async def _prefetch(ctx: Ctx, base: str, cursor: str, count: int) -> tuple[int | None, dict]:
    """Checkpoint size plus up to `count` full tiles from the cursor, fetched concurrently (a log is read faster than one round trip per tile)."""
    checkpoint = await sources.fetch_text(ctx, "ct_tiled", f"{base}/checkpoint", _headers(ctx, base))
    size = None if isinstance(checkpoint, sources.SourceError) else _checkpoint_size(checkpoint)
    if size is None:
        return None, {}
    first = int(cursor) // 256 * 256
    starts = [start for start in range(first, first + 256 * count, 256) if start + 256 <= size]
    results = await asyncio.gather(*(_read_tile(ctx, base, start, 256) for start in starts))
    return size, dict(zip(starts, results, strict=True))


_bad_tiles: dict[tuple[str, str], int] = {}  # (log, cursor) -> consecutive unparseable reads of that tile


async def run_once(log_url: str, cursor: str | None, ctx: Ctx) -> dict:
    """Read tiles until the tail (at most max_tiles_per_cycle), persisting candidates and cursor after every tile."""
    cfg = ctx.settings.sources["ct_tiled"].extra
    base = log_url.rstrip("/")
    result = {"status": "ok", "records": 0, "cursor": cursor}
    done = 0
    while done < cfg["max_tiles_per_cycle"]:
        size, tiles = (
            await _prefetch(
                ctx,
                base,
                cursor,
                min(
                    cfg["data_tile_concurrency"] if _data_mode(ctx, base) else cfg["tile_concurrency"],
                    cfg["max_tiles_per_cycle"] - done,
                ),
            )
            if cursor is not None
            else (None, {})
        )
        for _ in range(max(len(tiles), 1)):
            step = await _step(cursor, 256, ctx, log_url, size, tiles)
            done += 1
            result["size"] = step.size or result.get("size")
            if step.batch.status != "ok":
                result.update(status="error", error=step.batch.error)
                if step.batch.error != "bad_payload":
                    return result
                # a data tile that does not parse: retry with growing pauses, then skip it visibly instead of sticking on it forever
                tries = _bad_tiles[log_url, cursor] = _bad_tiles.get((log_url, cursor), 0) + 1
                if tries < cfg["bad_tile_retries"]:
                    result["retry_after_s"] = min(2**tries, cfg["backoff_max_s"])
                    return result
                del _bad_tiles[log_url, cursor]
                end = int(cursor) // 256 * 256 + 256
                end = min(end, step.size) if step.size else end
                await intake.store_candidates([], log_url, str(end), int(cfg["recheck_hours"] * 3600))
                result.update(
                    status="ok",
                    skipped={"from": int(cursor), "to": end, "from_ts": ctx.now(), "to_ts": ctx.now()},
                    cursor=str(end),
                )
                result.pop("error")
                cursor = str(end)
                continue
            _bad_tiles.pop((log_url, cursor), None)
            if step.batch.next_cursor == cursor:
                return result
            await intake.store_candidates(
                step.batch.candidates, log_url, step.batch.next_cursor, int(cfg["recheck_hours"] * 3600)
            )
            cursor = result["cursor"] = step.batch.next_cursor
            result["records"] += len(step.batch.candidates)
            if dropped := _dropped_unreported():
                result["generic_dropped"] = result.get("generic_dropped", 0) + dropped
            result["last_ts"] = step.last_ts
            if step.skipped:
                result["skipped"] = step.skipped
        if not tiles:
            break  # at the tail (or the checkpoint failed): next poll
    return result
