"""Queue one cheap `recheck` (DNS + feed match + current brand rules) for every open row of the analyst's "To check" and "Low signal" views.

    python -m scamshield.tools.requeue_rechecks [data_dir] [--dry-run]

Run it after the brand rules change: old rows keep their old brand answer until they are re-checked. Only inserts jobs, deletes nothing;
a second run on the same day (UTC) queues nothing new; rule fixes often keep rule_version, so the day is in the key too."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import UTC, datetime

from scamshield import config, db, worker
from scamshield.web import view


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("data_dir", nargs="?", default=os.environ.get("SCAMSHIELD_DATA_DIR") or "data")
    parser.add_argument("--dry-run", action="store_true", help="print the count and the first 20 names, queue nothing")
    args = parser.parse_args(argv)
    os.environ["SCAMSHIELD_DATA_DIR"] = args.data_dir
    settings = config.load()
    db.init(settings.db_path)
    version = settings.scoring["rule_version"]
    day = datetime.now(UTC).strftime("%Y-%m-%d")

    def requeue(conn) -> list[str]:
        q = view.queue(conn, settings)
        names = [r["fqdn"] for r in (*q["todo"], *q["low"]) if r["verdict"] is None and r["found_by"] != "baseline"]
        if not args.dry_run:
            for fqdn in names:
                worker.enqueue_in(conn, "recheck", fqdn, {}, f"recheck:{fqdn}:rules:{version}:{day}")
            conn.commit()
        return names

    names = asyncio.run(db.run(requeue))
    print(f"{len(names)} domains {'would be queued' if args.dry_run else 'queued (already queued ones are skipped)'}")
    if args.dry_run:
        print("\n".join(names[:20]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
