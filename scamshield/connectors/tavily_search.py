"""Web search for scam sites: Tavily keyless or with TAVILY_API_KEY, 24 h cache in search_results.
A result goes to the queue (only through intake.submit) when it is a brand lookalike, not official and not on the benign list (sources.yaml)."""

from __future__ import annotations

from datetime import datetime, timedelta
from urllib.parse import urlsplit

from scamshield import db, intake, sources
from scamshield.contracts import Ctx, Fact
from scamshield.enrich import lookalike

SOURCE = "tavily"
URL = "https://api.tavily.com/search"
FOUND_BY = "web search"
MAX_RESULTS = 10


def _is_official(host: str, brands) -> bool:
    return lookalike.is_official(host, brands)


def _is_benign(host: str, benign: list[str]) -> bool:
    return any(host == d or host.endswith(f".{d}") for d in benign)


def _cached(conn, query: str, since: str | None):
    """Rows of the newest ok run for this query; with `since`, only if it is not older than that."""
    run = conn.execute(
        "SELECT id, run_at FROM search_runs WHERE query = ? AND connector = ? AND status = 'ok' ORDER BY id DESC LIMIT 1",
        (query, SOURCE),
    ).fetchone()
    if run is None or (since and run["run_at"] < since):
        return None
    rows = conn.execute(
        """SELECT r.rank, r.url, r.title, r.is_official, d.fqdn FROM search_results r LEFT JOIN domains d ON d.id = r.domain_id
           WHERE r.run_id = ? ORDER BY r.rank""",
        (run["id"],),
    ).fetchall()
    return run["run_at"], [_row(r["rank"], r["url"], r["title"], bool(r["is_official"])) for r in rows]


def _row(rank: int, url: str, title: str | None, official: bool) -> dict:
    return {"rank": rank, "url": url, "title": title, "host": urlsplit(url).hostname, "is_official": official}


def _save(conn, query: str, now: str, status: str, error: str | None, rows: list[dict]) -> None:
    run_id = conn.execute(
        "INSERT INTO search_runs (query, connector, run_at, status, result_count, error) VALUES (?, ?, ?, ?, ?, ?)",
        (query, SOURCE, now, status, len(rows), error),
    ).lastrowid
    for row in rows:
        domain = conn.execute("SELECT id FROM domains WHERE fqdn = ?", (row["host"],)).fetchone()
        conn.execute(
            "INSERT INTO search_results (run_id, rank, url, domain_id, is_official, title, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                run_id,
                row["rank"],
                row["url"],
                domain["id"] if domain and not row["is_official"] else None,
                row["is_official"],
                row["title"],
                now,
            ),
        )
    conn.commit()


def _request(ctx: Ctx, query: str) -> tuple[dict, dict]:
    cfg = ctx.settings.sources[SOURCE].extra
    key = ctx.settings.secrets.get("TAVILY_API_KEY")
    headers = {"Authorization": f"Bearer {key}"} if key else {"X-Tavily-Access-Mode": "keyless"}
    return {"query": query, "country": cfg["country"], "max_results": MAX_RESULTS}, headers


async def search(ctx: Ctx, query: str) -> dict:
    """One query. {"status": ok|cached|error, "results": [...], "error", "cached_at"}; a hit younger than cache_hours makes no HTTP."""
    now = ctx.now()
    since = (
        (datetime.fromisoformat(now) - timedelta(hours=ctx.settings.sources[SOURCE].extra["cache_hours"]))
        .isoformat()
        .replace("+00:00", "Z")
    )
    hit = await db.run(_cached, query, since)
    if hit:
        return {"status": "cached", "results": hit[1], "error": None, "cached_at": hit[0]}
    body, headers = _request(ctx, query)
    payload = await sources.post_json(ctx, SOURCE, URL, body, headers)
    if not isinstance(payload, sources.SourceError) and not isinstance(
        payload.get("results") if isinstance(payload, dict) else None, list
    ):
        payload = sources.SourceError(SOURCE, "bad_payload")
    if isinstance(payload, sources.SourceError):
        await db.run(_save, query, now, "error", payload.reason, [])
        old = await db.run(_cached, query, None)
        return {
            "status": "error",
            "results": old[1] if old else [],
            "error": payload.reason,
            "cached_at": old[0] if old else None,
        }
    rows, seen = [], set()
    for item in payload["results"]:
        host = (urlsplit(item.get("url") or "").hostname or "").lower() if isinstance(item, dict) else ""
        if not host or host in seen:
            continue
        seen.add(host)
        rows.append(
            _row(len(rows) + 1, item["url"], item.get("title"), _is_official(host, ctx.settings.brands))
            | {"host": host}
        )
    benign = ctx.settings.sources[SOURCE].extra["benign_domains"]
    for row in rows:  # every result is saved below; only brand lookalikes outside the benign list reach the queue
        if (
            not row["is_official"]
            and not _is_benign(row["host"], benign)
            and (brand := lookalike.match(row["host"], ctx.settings.brands, "ct"))
        ):
            brand_fact = Fact("lookalike", lookalike.fact_value(brand), SOURCE, now, now, "ok")
            hit = Fact(
                "search_hit",
                {"query": query, "rank": row["rank"], "country": body["country"], "url": row["url"]},
                SOURCE,
                now,
                now,
                "ok",
            )
            await intake.submit(row["host"], FOUND_BY, [brand_fact, hit], 0)
    await db.run(_save, query, now, "ok", None, rows)
    return {"status": "ok", "results": rows, "error": None, "cached_at": None}


def not_checked(result: dict) -> str:
    return sources.not_checked_text("web search", result["error"])


async def run_once(ctx: Ctx) -> dict:
    """Every brand query once; stops at the first failure (a rate limit or budget will not clear within this run)."""
    queries = list(dict.fromkeys(q for brand in ctx.settings.brands for q in brand.search_queries))
    done, found, error = 0, 0, None
    for query in queries:
        result = await search(ctx, query)
        if result["status"] == "error":
            error = result["error"]
            break
        done, found = done + 1, found + len(result["results"])
    await db.run(sources.record_status, SOURCE, ctx.now(), error)
    return {"queries": done, "results": found, "error": error}
