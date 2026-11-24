"""Snapshot ONLY the official domains in config/brands.yaml and save their logo / page / favicon hashes to config/brand_refs.json.

    python -m scamshield.tools.build_brand_refs [brand_id ...]

Snapshot compares suspect pages with these hashes. Run it again when an official site changes its logo."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from scamshield import config, snapshot

OFFICIAL_MAX_BYTES = 60_000_000  # official sites are heavy (rta.ae > 10 MB); the lower stop is for suspect pages
OFFICIAL_MAX_REQUESTS = 800  # bank and government home pages load hundreds of files; 150 is the stop for suspect pages


def drop_shared_logos(brands: dict, max_distance: int) -> list[str]:
    """A logo hash seen on the official sites of two different brands is a common icon (store badge, cookie banner), not a brand logo."""

    def close(a, b):
        return (int(a, 16) ^ int(b, 16)).bit_count() <= max_distance

    owners = [(bid, e) for bid, entries in brands.items() for e in entries if e.get("logo")]
    shared = {id(e) for bid, e in owners for other, f in owners if other != bid and close(e["logo"], f["logo"])}
    dropped = []
    for bid, e in owners:
        if id(e) in shared:
            dropped.append(f"{bid}:{e['domain']}")
            e["logo"] = None
    return dropped


async def build(settings, only: set[str] | None = None, out: Path = snapshot.REFS_PATH, grab=snapshot.capture) -> dict:
    """Existing entries of brands not rebuilt are kept; a domain that fails (or now gives no usable hash) keeps its previous entry and is listed under "failed"."""
    try:
        data = json.loads(out.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {"brands": {}}
    rebuilt = {d for b in settings.brands if not only or b.id in only for d in b.official_domains}
    data["failed"] = {
        d: why for d, why in data.get("failed", {}).items() if d not in rebuilt
    }  # failures of brands not rebuilt now stay listed
    with tempfile.TemporaryDirectory() as tmp:
        for brand in settings.brands:
            if only and brand.id not in only:
                continue
            entries, before = [], {e["domain"]: e for e in data["brands"].get(brand.id, [])}
            for domain in brand.official_domains:
                result = await grab(
                    f"https://{domain}/",
                    settings,
                    Path(tmp) / domain,
                    max_bytes=OFFICIAL_MAX_BYTES,
                    max_requests=OFFICIAL_MAX_REQUESTS,
                )
                if result.status != "ok" and not domain.startswith(
                    "www."
                ):  # many official sites answer only on www (aramex.com, mashreq.com, liv.me)
                    result = await grab(
                        f"https://www.{domain}/",
                        settings,
                        Path(tmp) / f"www.{domain}",
                        max_bytes=OFFICIAL_MAX_BYTES,
                        max_requests=OFFICIAL_MAX_REQUESTS,
                    )
                entry = {
                    "domain": domain,
                    "page": snapshot.usable_hash(result.hashes.get("page")),
                    "logo": snapshot.usable_hash(result.hashes.get("logo")),
                    "favicon": result.hashes.get("favicon"),
                }
                if result.status != "ok":
                    data["failed"][domain] = result.reason
                old = before.get(domain)
                if old and (
                    result.status != "ok" or (old.get("logo") and not entry["logo"])
                ):  # official sites are flaky (bot walls, timeouts): never lose a good reference
                    entry = old
                if result.status == "ok" or entry is old:
                    entries.append(entry)
            data["brands"][brand.id] = entries
    data["shared_logos_dropped"] = drop_shared_logos(data["brands"], settings.scoring["snapshot"]["logo_max_distance"])
    data["built_at"] = datetime.now(UTC).strftime("%Y-%m-%d")
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return data


if __name__ == "__main__":
    result = asyncio.run(build(config.load(), set(sys.argv[1:]) or None))
    print(
        f"built {result['built_at']}: {sum(len(v) for v in result['brands'].values())} official pages, failed: {result['failed']}"
    )
