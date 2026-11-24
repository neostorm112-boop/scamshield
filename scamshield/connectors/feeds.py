"""Phishing lists: download every feed, swap the lookup index atomically, send brand lookalikes through intake."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
from urllib.parse import urlsplit

from scamshield import db, intake, sources, worker
from scamshield.contracts import Candidate, Ctx
from scamshield.enrich.lookalike import fact_value, match

_HOST = re.compile(r"[a-z0-9._-]+\.[a-z0-9-]+")
_CHUNK = 50_000  # rows per commit, so CT and the worker are not locked out while 500k rows are written


def _parse(text: str) -> set[str]:
    """Hostnames from a list that holds either bare domains or URLs; comments, IPs and non-ASCII names are skipped."""
    found = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        host = (urlsplit(line).hostname if "://" in line else line.split()[0].rstrip(".")) or ""
        if _HOST.fullmatch(host):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                found.add(host)
    return found


def _urls(text: str) -> dict[str, str]:
    """host -> first full URL, for list lines that are URLs: the path is the only context a short brand keyword gets in feed mode."""
    found = {}
    for line in text.splitlines():
        line = line.strip().lower()
        host = urlsplit(line).hostname if "://" in line else None
        if host and _HOST.fullmatch(host):
            found.setdefault(host, line)
    return found


def _swap(conn, parsed: dict[str, set[str]], failed: dict[str, str], now: str) -> tuple[list[str], list[str]]:
    """Returns (new domains, new baseline domains): a feed loaded for the first time is its own baseline, so a feed that failed on
    the first run does not flood the Feed later. Build feed_index_new from the fresh lists (plus old rows of feeds that failed), swap it in, record statuses."""
    old = {
        row["domain"]: (set(row["sources"].split(",")), row["first_listed_at"], row["last_listed_at"])
        for row in conn.execute("SELECT domain, sources, first_listed_at, last_listed_at FROM feed_index")
    }
    new = {}
    for domain, (names, first, last) in old.items():
        if names & failed.keys():
            new[domain] = [names & failed.keys(), first, last]
    for name, domains in parsed.items():
        for domain in domains:
            entry = new.setdefault(domain, [set(), old[domain][1] if domain in old else now, now])
            entry[0].add(name)
            entry[2] = now
    first_time = {
        name
        for name in parsed
        if conn.execute("SELECT 1 FROM feed_meta WHERE key = ?", (f"feed:{name}",)).fetchone() is None
    }
    baseline = {d for d in new if d not in old and all(n in first_time for n in new[d][0])}

    conn.execute("DROP TABLE IF EXISTS feed_index_new")
    conn.execute(
        "CREATE TABLE feed_index_new (domain TEXT PRIMARY KEY, sources TEXT NOT NULL, first_listed_at TEXT, last_listed_at TEXT)"
    )
    rows = [(d, ",".join(sorted(e[0])), e[1], e[2]) for d, e in new.items()]
    for start in range(0, len(rows), _CHUNK):
        conn.executemany("INSERT INTO feed_index_new VALUES (?, ?, ?, ?)", rows[start : start + _CHUNK])
        conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DROP TABLE feed_index")
        conn.execute("ALTER TABLE feed_index_new RENAME TO feed_index")
        meta = "INSERT INTO feed_meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        for name, domains in parsed.items():
            conn.execute(meta, (f"feed:{name}", json.dumps({"fetched_at": now, "count": len(domains)})))
            conn.execute(
                """INSERT INTO sources (name, kind, status, last_success_at) VALUES (?, 'connector', 'ok', ?)
                         ON CONFLICT(name) DO UPDATE SET status = 'ok', last_success_at = excluded.last_success_at""",
                (f"feeds:{name}", now),
            )
        for name, reason in failed.items():
            conn.execute(
                """INSERT INTO sources (name, kind, status, last_error, last_error_at) VALUES (?, 'connector', 'stale', ?, ?)
                         ON CONFLICT(name) DO UPDATE SET status = 'stale', last_error = excluded.last_error, last_error_at = excluded.last_error_at""",
                (f"feeds:{name}", reason, now),
            )
        if parsed:
            conn.execute("INSERT OR IGNORE INTO feed_meta (key, value) VALUES ('baseline_done_at', ?)", (now,))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return [d for d in new if d not in old and d not in baseline], sorted(baseline)


def _lookalikes(domains: list[str], brands, source: str, now: str, urls: dict[str, str]) -> list[Candidate]:
    candidates = []
    for domain in domains:
        url = urls.get(domain)
        hit = match(domain, brands, mode="feed", url_path=urlsplit(url).path if url else None)
        if hit:
            metadata = {**fact_value(hit), **({"url": url} if url else {})}
            candidates.append(Candidate(domain, source, now, "LIVE", metadata))
    return candidates


async def run_once(ctx: Ctx) -> dict:
    """One refresh. Returns {"failed": {feed: reason}}; a failed feed keeps its old rows and shows as stale."""
    cfg = ctx.settings.sources["feeds"]
    now = ctx.now()
    parsed, failed, urls = {}, {}, {}
    for name, url in cfg.extra["urls"].items():
        text = await sources.fetch_text_limited(ctx, "feeds", url, cfg.extra["max_bytes"])
        if isinstance(text, sources.SourceError):
            failed[name] = text.reason
        else:
            parsed[name] = await asyncio.to_thread(_parse, text)
            urls.update(await asyncio.to_thread(_urls, text))
    fresh, baseline = await db.run(_swap, parsed, failed, now)
    await db.run(worker.recheck_listed, {*fresh, *baseline}, now)
    candidates = await asyncio.to_thread(
        lambda: (
            _lookalikes(baseline, ctx.settings.brands, "baseline", now, urls)
            + _lookalikes(fresh, ctx.settings.brands, "feeds", now, urls)
        )
    )
    await intake.store_candidates(candidates, "feeds", None, int(cfg.extra["refresh_hours"] * 3600))
    return {"failed": failed}
