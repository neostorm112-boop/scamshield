"""Run the real check pipeline (sieve -> intake -> worker -> assessment) over a labelled set and print one table.

    python -m scamshield.tools.check_set fixtures/test/set20.csv  [--feeds]

CSV columns: domain, expected (OFFICIAL | FAKE), synthetic (1 for an invented name), proof. The data dir is a fresh temp dir.
Exit code 1 when an official domain is not OFFICIAL, a fake is in NOISE, or a domain took more than the limit."""

from __future__ import annotations

import asyncio
import csv
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import httpx

from scamshield import config, db, intake, runtime, sources, worker
from scamshield.connectors.feeds import _parse, _swap
from scamshield.contracts import Fact
from scamshield.enrich.lookalike import fact_value, match

LIMIT_S = 60


async def _check(domain: str, settings, http) -> tuple[str, float]:
    hit = match(domain, settings.brands, "ct")
    now = intake._now()
    evidence = [Fact("lookalike", fact_value(hit), "lookalike", now, now, "ok")] if hit else []
    await intake.submit(domain, "manual", evidence, 10)
    await worker.process_next(settings, http)

    def read(conn):
        row = conn.execute(
            """SELECT a.components_json FROM assessments a JOIN domains d ON d.id = a.domain_id
                              WHERE d.fqdn = ? ORDER BY a.id DESC LIMIT 1""",
            (domain,),
        ).fetchone()
        return row[0] if row else None

    return await db.run(read)


async def _load_feeds(settings, http) -> None:
    """Fill the phishing-list index so listed names score feed points; no candidates are queued, so only the set is checked."""
    ctx = runtime.make_ctx(settings, http, "manual")
    cfg = settings.sources["feeds"]
    parsed, failed = {}, {}
    for name, url in cfg.extra["urls"].items():
        text = await sources.fetch_text_limited(ctx, "feeds", url, cfg.extra["max_bytes"])
        if isinstance(text, sources.SourceError):
            failed[name] = text.reason
        else:
            parsed[name] = _parse(text)
    await db.run(_swap, parsed, failed, ctx.now())
    print(f"feeds loaded: {sorted(parsed)}, failed: {failed}", file=sys.stderr)


async def run(path: str, out=sys.stdout, feeds: bool = False) -> int:
    os.environ["SCAMSHIELD_DATA_DIR"] = tempfile.mkdtemp(prefix="check_set_")
    settings = config.load()
    db.init(settings.db_path)
    rows = list(csv.DictReader(Path(path).read_text(encoding="utf-8").splitlines()))
    print(f"{'domain':<58} {'expected':<9} {'band':<15} {'points':>6} {'seconds':>7}", file=out)
    failed = 0
    async with httpx.AsyncClient(headers={"Accept-Encoding": "gzip, identity"}) as http:
        if feeds:
            await _load_feeds(settings, http)
        for row in rows:
            started = time.monotonic()
            try:
                raw = await asyncio.wait_for(_check(row["domain"], settings, http), LIMIT_S)
                parts = json.loads(raw) if raw else {}
                band, points = parts.get("band", "NO_ASSESSMENT"), parts.get("P", 0)
            except TimeoutError:
                band, points = "TIMEOUT", 0
            seconds = time.monotonic() - started
            bad = (
                band in ("TIMEOUT", "NO_ASSESSMENT")
                or (row["expected"] == "OFFICIAL" and band != "OFFICIAL")
                or (row["expected"] == "FAKE" and band == "NOISE")
            )
            failed += bad
            print(
                f"{row['domain'] + (' [synthetic]' if row['synthetic'] == '1' else ''):<58} {row['expected']:<9} {band:<15} {points:>6g} {seconds:>7.1f}{'  FAIL' if bad else ''}",
                file=out,
            )
    print(f"{len(rows)} domains, {failed} failed", file=out)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(run(sys.argv[1], feeds="--feeds" in sys.argv[2:])))
