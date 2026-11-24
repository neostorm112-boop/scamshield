"""The only place a Ctx is assembled, plus the request budget stored in the `budgets` table."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from dns import asyncresolver

from scamshield import db
from scamshield.contracts import Ctx, Settings


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _windows(cfg, moment: datetime) -> list[tuple[str, int]]:
    """(window_start, limit) for each limit the source has; hour and day windows are UTC."""
    windows = []
    if cfg.budget_per_hour is not None:
        windows.append((moment.strftime("%Y-%m-%dT%H:00:00Z"), cfg.budget_per_hour))
    if cfg.budget_per_day is not None:
        windows.append((moment.strftime("%Y-%m-%d"), cfg.budget_per_day))
    return windows


def _used(conn, source: str, window_start: str) -> dict[str, int]:
    rows = conn.execute("SELECT pool, used FROM budgets WHERE source = ? AND window_start = ?", (source, window_start))
    return {row["pool"]: row["used"] for row in rows}


def _take(conn, cfg, source: str, pool: str, moment: datetime) -> bool:
    reserve = cfg.extra.get("reserve_manual")
    conn.execute("BEGIN IMMEDIATE")  # check-and-increment must not interleave with another thread
    try:
        windows = _windows(cfg, moment)
        for start, limit in windows:
            used = _used(conn, source, start)
            if reserve is None:
                full = sum(used.values()) >= limit
            else:
                full = used.get(pool, 0) >= (reserve if pool == "manual" else limit - reserve)
            if full:
                conn.rollback()
                return False
        for start, _ in windows:
            conn.execute(
                """INSERT INTO budgets (source, pool, window_start, used) VALUES (?, ?, ?, 1)
                   ON CONFLICT(source, pool, window_start) DO UPDATE SET used = used + 1""",
                (source, pool, start),
            )
        conn.commit()
        return True
    except BaseException:
        conn.rollback()
        raise


def _remaining(conn, cfg, source: str, moment: datetime) -> dict:
    """CONTRACTS shape {"manual": n, "auto": n, "resets_at": iso}; the tightest window wins."""
    windows = _windows(cfg, moment)
    if not windows:
        return {"manual": None, "auto": None, "resets_at": None}
    reserve = cfg.extra.get("reserve_manual")
    left = {"manual": None, "auto": None}
    for start, limit in windows:
        used = _used(conn, source, start)
        if reserve is None:
            free = limit - sum(used.values())
            pools = {"manual": free, "auto": free}
        else:
            pools = {"manual": reserve - used.get("manual", 0), "auto": limit - reserve - used.get("auto", 0)}
        for pool, value in pools.items():
            left[pool] = max(0, value if left[pool] is None else min(left[pool], value))
    hourly = cfg.budget_per_hour is not None
    reset = (
        (moment.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1))
        if hourly
        else (moment.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1))
    )
    return {**left, "resets_at": reset.isoformat().replace("+00:00", "Z")}


class DbBudget:
    def __init__(self, settings: Settings):
        self._settings = settings

    async def take(self, source: str, pool: str = "auto") -> bool:
        cfg = self._settings.sources.get(source)
        if cfg is None or (cfg.budget_per_hour is None and cfg.budget_per_day is None):
            return True
        return await db.run(_take, cfg, source, pool, datetime.now(UTC))

    async def remaining(self, source: str) -> dict:
        cfg = self._settings.sources.get(source)
        return (
            await db.run(_remaining, cfg, source, datetime.now(UTC))
            if cfg
            else {"manual": None, "auto": None, "resets_at": None}
        )


def make_ctx(settings: Settings, http, pool: str) -> Ctx:
    return Ctx(settings, http, asyncresolver.Resolver(), DbBudget(settings), pool, _utc_now)
