"""Is the domain in the phishing-list index? An index that is missing or old is reported as such, never as "not listed"."""

from __future__ import annotations

import json
from datetime import datetime, timedelta

from scamshield import db, sources
from scamshield.contracts import Ctx, Fact
from scamshield.netsafe import registrable_of


def _lookup(conn, names: list[str], fqdn: str):
    fetched = [
        json.loads(row["value"])["fetched_at"]
        for row in conn.execute(
            f"SELECT value FROM feed_meta WHERE key IN ({','.join('?' * len(names))})", [f"feed:{n}" for n in names]
        )
    ]
    hit = conn.execute(
        "SELECT * FROM feed_index WHERE domain IN (?, ?) ORDER BY domain = ? DESC",
        (fqdn, registrable_of(fqdn) or fqdn, fqdn),
    ).fetchone()
    return fetched, dict(hit) if hit else None


async def run(fqdn: str, ctx: Ctx) -> list[Fact]:
    fetched_at = ctx.now()
    cfg = ctx.settings.sources["feeds"]
    if not cfg.enabled:
        return sources.error_facts(("in_feed",), sources.SourceError("feed_match", "disabled"), fetched_at)
    names = list(cfg.extra["urls"])
    loaded, hit = await db.run(_lookup, names, fqdn)
    if not loaded:
        return sources.error_facts(("in_feed",), sources.SourceError("feed_match", "not_loaded"), fetched_at)
    list_from = min(loaded)
    # a feed that never loaded counts as stale: the domain was not checked against it
    stale = len(loaded) < len(names) or datetime.fromisoformat(list_from) < datetime.fromisoformat(
        fetched_at
    ) - timedelta(hours=cfg.extra["stale_hours"])
    if hit:
        value = {
            "listed": True,
            "feeds": hit["sources"].split(","),
            "first_listed_at": hit["first_listed_at"],
            "stale": stale,
        }
        return [Fact("in_feed", value, "feed_match", hit["first_listed_at"], list_from, "ok")]
    if stale:
        return sources.error_facts(("in_feed",), sources.SourceError("feed_match", "stale"), list_from)
    return [Fact("in_feed", {"listed": False}, "feed_match", None, list_from, "ok")]
