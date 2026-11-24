"""urlscan.io search: pages that carry a brand's title (or official favicon file hash) on a domain that is not the brand's own.
Only the observed page facts are stored; urlscan's own verdicts/labels are never read (not evidence). Pages are never fetched, only the search API is called."""

from __future__ import annotations

import ipaddress
from urllib.parse import quote, urlsplit

from scamshield import db, intake, snapshot, sources
from scamshield.connectors.tavily_search import _is_benign, _is_official
from scamshield.contracts import Ctx, Fact
from scamshield.enrich import lookalike

SOURCE = "urlscan"
FOUND_BY = "urlscan"


def _queries(cfg: dict, refs: dict | None = None) -> list[tuple[str, str, str]]:
    """(brand id, match kind, Lucene query) from sources.yaml, plus one query per brand over the SHA-256 of its official favicon files
    (config/brand_refs.json) when favicons_from_refs is on: a kit copies the favicon whatever the domain name is (17 fake Dubai Customs sites)."""
    queries = []
    for brand, spec in cfg["queries"].items():
        queries += [(brand, "title", f'page.title:"{title}"') for title in spec.get("title", [])]
        queries += [(brand, "favicon", f'hash:"{sha}"') for sha in spec.get("favicon_sha256", [])]
    if cfg.get("favicons_from_refs"):
        for brand, rows in sorted((refs if refs is not None else snapshot._refs()).items()):
            hashes = sorted({row["favicon"] for row in rows if row.get("favicon")})
            if hashes:
                queries.append((brand, "favicon", "hash:(" + " OR ".join(f'"{sha}"' for sha in hashes) + ")"))
    return queries


async def _search(ctx: Ctx, cfg: dict, key: str, query: str) -> list | sources.SourceError:
    q = quote(f"{query} AND date:>now-{cfg['lookback_days']}d")
    payload = await sources.fetch_json(ctx, SOURCE, f"{cfg['url']}?q={q}&size={cfg['size']}", {"api-key": key})
    if isinstance(payload, sources.SourceError):
        return payload
    results = payload.get("results") if isinstance(payload, dict) else None
    return results if isinstance(results, list) else sources.SourceError(SOURCE, "bad_payload")


def _suspicious_host(host: str, url: str, brands) -> bool:
    """A title hit is queued only with a second sign: brand-like name or path, the smishing shape, or a cheap TLD (scoring.yaml smishing.tlds)."""
    path = urlsplit(url).path if url else ""
    return bool(
        lookalike.match(host, brands, "feed", url_path=path or None)
        or (path and lookalike.path_match(host, brands, path))
        or lookalike.smishing_pattern(host)
        or host.rsplit(".", 1)[-1] in lookalike._scoring()["smishing"]["tlds"]
    )


async def _submit(ctx: Ctx, brand: str, kind: str, results: list, now: str) -> int:
    benign = ctx.settings.sources["tavily"].extra["benign_domains"]
    queued, newest = 0, {}
    for item in results:  # urlscan lists every scan; one fact per host per query, from its newest scan
        host = str((item.get("page") or {}).get("domain") or "").lower()
        if host and (
            host not in newest
            or str((item.get("task") or {}).get("time") or "") > str((newest[host].get("task") or {}).get("time") or "")
        ):
            newest[host] = item
    for item in newest.values():
        page, task = (item.get("page") or {}), (item.get("task") or {})
        host = str(page.get("domain") or "").lower()
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        if (
            "." not in host
            or _is_official(host, ctx.settings.brands)
            or _is_benign(host, benign)
            or not task.get("uuid")
        ):
            continue
        if kind == "title" and not _suspicious_host(host, str(page.get("url") or ""), ctx.settings.brands):
            continue  # a news or directory page titled "RTA ..." is not a candidate; the title alone is not enough
        fact = Fact(
            "urlscan_hit",
            {
                "brand": brand,
                "match": kind,
                "title": page.get("title"),
                "scan_date": task.get("time"),
                "result_url": f"https://urlscan.io/result/{task['uuid']}/",
            },
            SOURCE,
            task.get("time"),
            now,
            "ok",
        )
        await intake.submit(host, FOUND_BY, [fact], 0)
        queued += 1
    return queued


async def run_once(ctx: Ctx) -> dict:
    """Every configured query once; stops at the first failure (a budget or rate limit will not clear within this run). No key -> "off", no request."""
    cfg = ctx.settings.sources[SOURCE]
    now = ctx.now()
    key = ctx.settings.secrets.get(cfg.key_env or "")
    if not key:
        await db.run(sources.record_status, SOURCE, now, None, True)
        return {"queries": 0, "candidates": 0, "error": None}
    done, queued, error = 0, 0, None
    for brand, kind, query in _queries(cfg.extra):
        results = await _search(ctx, cfg.extra, key, query)
        if isinstance(results, sources.SourceError):
            error = results.reason
            break
        done += 1
        queued += await _submit(ctx, brand, kind, results, now)
    await db.run(sources.record_status, SOURCE, now, error)
    return {"queries": done, "candidates": queued, "error": error}
