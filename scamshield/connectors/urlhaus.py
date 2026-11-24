"""URLhaus (abuse.ch) recent online URLs: host + path go through the brand sieve in feed mode (a brand word in the PATH counts) or the smishing
pattern; matches reach the queue through intake with a "listed in URLhaus" fact. The listed pages are never fetched."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from urllib.parse import urlsplit

from scamshield import db, intake, sources
from scamshield.connectors.tavily_search import _is_benign
from scamshield.contracts import Candidate, Ctx, Fact
from scamshield.enrich.lookalike import fact_value, match, path_match, smishing_pattern

SOURCE = "urlhaus"


def _iso(added: str | None) -> str | None:
    """URLhaus dates look like "2026-11-20 14:03:05 UTC"."""
    try:
        return (
            datetime.strptime(added or "", "%Y-%m-%d %H:%M:%S UTC")
            .replace(tzinfo=UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except ValueError:
        return None


def _candidates(items: list, ctx: Ctx, now: str) -> list[Candidate]:
    benign = ctx.settings.sources["tavily"].extra["benign_domains"]
    found, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or item.get("url_status") != "online":
            continue
        url = str(item.get("url") or "").strip()
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or "." not in host or host in seen or _is_benign(host, benign):
            continue
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        hit = (
            match(host, ctx.settings.brands, "feed", parts.path)
            or path_match(host, ctx.settings.brands, parts.path)
            or smishing_pattern(host)
        )
        if not hit:
            continue
        seen.add(host)
        added = _iso(item.get("date_added"))
        listed = Fact(
            "urlhaus_listed",
            {
                "url": url,
                "threat": item.get("threat"),
                "tags": item.get("tags") or [],
                "date_added": added,
                "reference": item.get("urlhaus_reference"),
            },
            SOURCE,
            added,
            now,
            "ok",
        )
        found.append(Candidate(host, SOURCE, now, "LIVE", {**fact_value(hit), "url": url, "facts": [listed]}))
    return found


async def run_once(ctx: Ctx) -> dict:
    """One pull of the recent-URLs list. No key -> status "off", no request. {"candidates": n, "error": reason | None}."""
    cfg = ctx.settings.sources[SOURCE]
    now = ctx.now()
    key = ctx.settings.secrets.get(cfg.key_env or "")
    if not key:
        await db.run(sources.record_status, SOURCE, now, None, True)
        return {"candidates": 0, "error": None}
    payload = await sources.fetch_json(ctx, SOURCE, cfg.extra["url"], {"Auth-Key": key})
    if not isinstance(payload, sources.SourceError) and not isinstance(
        payload.get("urls") if isinstance(payload, dict) else None, list
    ):
        payload = sources.SourceError(SOURCE, "bad_payload")
    if isinstance(payload, sources.SourceError):
        await db.run(sources.record_status, SOURCE, now, payload.reason)
        return {"candidates": 0, "error": payload.reason}
    candidates = _candidates(payload["urls"], ctx, now)
    await intake.store_candidates(candidates, SOURCE, None, int(cfg.extra["refresh_hours"] * 3600))
    await db.run(sources.record_status, SOURCE, now)
    return {"candidates": len(candidates), "error": None}
