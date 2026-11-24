"""Newly registered domains (smet.cz, CC BY 4.0): yesterday's and today's list, only names not seen before, through the same filters as ct_tiled
(brand, smishing pattern, generic name inside the shared hourly budget). The files are sorted and grow in the middle, so a line count is no cursor:
seen names are kept as 8-byte hashes in a small file per day next to the database (days older than yesterday are deleted)."""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import date, timedelta
from pathlib import Path

from scamshield import db, intake, live, sources
from scamshield.connectors.ct_tiled import _generic_slot
from scamshield.contracts import Candidate, Ctx
from scamshield.enrich.lookalike import (
    fact_value,
    generic_name,
    match,
    smishing_pattern,
)

SOURCE = "nrd"
_HOST = re.compile(
    r"[a-z0-9-]+(\.[a-z0-9-]+)+"
)  # IDN names arrive as xn--; anything else (blank, comment, unicode, junk) is skipped
_seen: dict[str, set[int]] = {}


def _hash(name: str) -> int:
    return int.from_bytes(hashlib.blake2b(name.encode(), digest_size=8).digest(), "big")


def _seen_file(ctx: Ctx, day: str) -> Path:
    return Path(ctx.settings.data_dir) / f"nrd_seen_{day}.bin"


def _load_seen(ctx: Ctx, day: str) -> set[int]:
    if day not in _seen:
        path = _seen_file(ctx, day)
        data = path.read_bytes() if path.exists() else b""
        _seen[day] = {int.from_bytes(data[i : i + 8], "big") for i in range(0, len(data) - 7, 8)}
    return _seen[day]


def _remember(ctx: Ctx, day: str, hashes: list[int]) -> None:
    _seen[day].update(hashes)
    path = _seen_file(ctx, day)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as out:
        out.write(b"".join(h.to_bytes(8, "big") for h in hashes))


_validators: dict[
    str, dict
] = {}  # ETag / Last-Modified per day URL: an unchanged file is not downloaded again (smet.cz supports both)


def _forget_old(ctx: Ctx, keep: list[str]) -> None:
    for url in [u for u in _validators if not any(day in u for day in keep)]:
        del _validators[url]
    for day in [d for d in _seen if d not in keep]:
        del _seen[day]
    for path in Path(ctx.settings.data_dir).glob("nrd_seen_*.bin"):
        if path.stem.removeprefix("nrd_seen_") not in keep:
            path.unlink(missing_ok=True)


def _parse(text: str, seen: set[int]) -> list[tuple[int, str]]:
    """(hash, name) of the valid lines not seen yet, once each."""
    found = {}
    for line in text.splitlines():
        name = line.strip().lower().rstrip(".")
        if _HOST.fullmatch(name) and (h := _hash(name)) not in seen:
            found[h] = name
    return list(found.items())


def _classify(names: list[str], ctx: Ctx) -> list[tuple[str, dict]]:
    """Pure CPU filtering (about 0.3 ms a name), run in a thread so it does not stall the event loop."""
    found = []
    for name in names:
        hit = match(name, ctx.settings.brands) or smishing_pattern(name)
        generic = (
            None
            if hit
            else generic_name(name, ctx.settings.scoring, ctx.settings.shared_infra.get("host_suffixes", []))
        )
        if hit or generic:
            found.append((name, hit or generic))
    return found


_generic_nrd = {
    "hour": "",
    "taken": 0,
    "seen": set(),
    "dropped": 0,
    "reported": 0,
}  # own hourly pool, see ct_tiled._generic_slot


def _candidates(hits: list[tuple[str, dict]], ctx: Ctx) -> list[Candidate]:
    """Generic hits take a slot of the shared hourly budget (one per apex); the slot is spent here, in the loop, not in the thread."""
    found = []
    for name, hit in hits:
        if hit["mode"] == "generic":
            if not _generic_slot(ctx, hit["apex"], _generic_nrd, "nrd_budget_per_hour"):
                continue
            name = hit["host"]
        found.append(Candidate(name, SOURCE, ctx.now(), "LIVE", fact_value(hit)))
    return found


async def _read_day(ctx: Ctx, day: str) -> int | sources.SourceError:
    """Download one day's file and queue the new names that pass the filters, in short batches. Returns the number of candidates."""
    cfg = ctx.settings.sources[SOURCE]
    text = await sources.fetch_text_limited(
        ctx, SOURCE, cfg.extra["url"].format(day=day), cfg.extra["max_bytes"], _validators
    )
    if isinstance(text, sources.SourceError):
        return 0 if text.reason == "not_modified" else text
    seen = await asyncio.to_thread(_load_seen, ctx, day)  # ~700k hashes after a restart: off the event loop
    fresh = await asyncio.to_thread(_parse, text, seen)
    stored = 0
    step = cfg.extra["batch_lines"]
    for start in range(0, len(fresh), step):
        part = fresh[start : start + step]
        candidates = _candidates(await asyncio.to_thread(_classify, [name for _, name in part], ctx), ctx)
        await intake.store_candidates(candidates, SOURCE, None, int(cfg.extra["refresh_hours"] * 3600))
        _remember(ctx, day, [h for h, _ in part])  # after the write: a crash re-reads this batch, never loses it
        stored += len(candidates)
        await asyncio.sleep(0)  # let CT and the worker run between batches
    return stored


async def run_once(ctx: Ctx) -> dict:
    """One pull: yesterday (the tail it still lacked) and today. {"candidates": n, "error": reason | None}; a missing yesterday file is not an error."""
    today = date.fromisoformat(ctx.now()[:10])
    days = [(today - timedelta(days=1)).isoformat(), today.isoformat()]
    _forget_old(ctx, days)
    total, error = 0, None
    for day in days:
        result = await _read_day(ctx, day)
        if isinstance(result, sources.SourceError):
            if not (day == days[0] and result.reason == "http_404"):
                error = result.reason
        else:
            total += result
    await db.run(sources.record_status, SOURCE, ctx.now(), error)
    await db.run(lambda conn: live.beat(conn, SOURCE, error is None, candidates=total, error=error))
    return {"candidates": total, "error": error}
