"""Live mode: heartbeats, the /healthz snapshot, the banner state and the counters shown on screen."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import urlsplit

from scamshield import config

_last: dict[str, datetime] = {}  # last worker beat of this process, for pause detection
_GST = timezone(timedelta(hours=4))
# "Finds by us" = domains whose latest assessment band is GRAY or FURTHER (not NOISE / OFFICIAL / GRAY_LOW / not yet assessed)
FIND_BANDS = (
    "(SELECT json_extract(a.components_json, '$.band') FROM assessments a WHERE a.domain_id = {alias}.id "
    "ORDER BY a.id DESC LIMIT 1) IN ('GRAY', 'FURTHER')"
)


def cfg() -> dict:
    return config._yaml(config.CONFIG_DIR / "live.yaml")


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_ts(value: str | None) -> datetime | None:
    """SQLite 'YYYY-MM-DD HH:MM:SS' and ISO '...Z' are both UTC."""
    try:
        moment = datetime.fromisoformat(value or "")
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def ct_loop(log_url: str) -> str:
    """ct:<operator label>[/<shard>]: one name per log shard; willow 2026h2 and 2027h1 under one name mixed two trees (M1, CT coverage, read 2.33%)."""
    parts = urlsplit(log_url)
    labels = (parts.hostname or log_url).split(".")
    shard = parts.path.strip("/").rsplit("/", 1)[-1] if parts.hostname else ""
    if (
        not shard and len(labels) > 2 and re.search(r"\d{4}h[12]$", labels[0])
    ):  # shard in the host name (Geomys tuscolo2026h2.skylight.geomys.org): four logs under "ct:skylight" mixed four trees
        return f"ct:{labels[1]}/{labels[0]}"
    return f"ct:{labels[1] if len(labels) > 2 else labels[0]}" + (f"/{shard}" if shard else "")


def beat(
    conn,
    loop: str,
    ok: bool = True,
    *,
    entries=None,
    tree_size=None,
    skipped=None,
    candidates=None,
    lag_s=None,
    error=None,
    cursor=None,
    now: datetime | None = None,
) -> None:
    """One proof that a loop ran. A worker beat far later than the previous one in the same process is a pause (lid closed, sleep)."""
    now = now or datetime.now(UTC)
    if loop == "worker":
        previous = _last.get("worker")
        _last["worker"] = now
        if previous and (now - previous).total_seconds() > cfg()["pause_gap_s"]:
            conn.execute(
                "INSERT INTO heartbeats (at, loop, ok, lag_s, error) VALUES (?, 'pause', 0, ?, ?)",
                (iso(now), int((now - previous).total_seconds()), "no heartbeat: machine asleep or process frozen"),
            )
    conn.execute(
        "INSERT INTO heartbeats (at, loop, ok, entries, tree_size, skipped, candidates, lag_s, error, cursor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (iso(now), loop, int(ok), entries, tree_size, skipped, candidates, lag_s, error, cursor),
    )
    conn.commit()


def ct_beat(conn, log_url: str, cursor_before: str | None, result: dict, now: datetime | None = None) -> None:
    """Heartbeat of one CT cycle: entries read, tree size, entries jumped, brand hits, lag while behind."""
    now = now or datetime.now(UTC)
    skipped = (result.get("skipped") or {}).get("to", 0) - (result.get("skipped") or {}).get("from", 0)
    delta = (
        int(result["cursor"]) - int(cursor_before)
        if cursor_before is not None and result.get("cursor") is not None
        else 0
    )
    behind = (result.get("size") or 0) - int(result["cursor"]) if result.get("cursor") is not None else 0
    last_ts = parse_ts(result.get("last_ts"))
    beat(
        conn,
        ct_loop(log_url),
        result["status"] == "ok",
        entries=max(delta - skipped, 0),
        tree_size=result.get("size"),
        skipped=skipped,
        candidates=result.get("records"),
        lag_s=int((now - last_ts).total_seconds()) if behind > 0 and last_ts else 0,
        error=result.get("error"),
        cursor=int(result["cursor"]) if result.get("cursor") is not None else None,
        now=now,
    )


def _stale_limit(loop: str, conf: dict) -> int:
    return conf["stale_s"].get(loop, conf["stale_s"]["default"])


def health(conn, now: datetime | None = None) -> dict:
    now = now or datetime.now(UTC)
    conf = cfg()
    boot = conn.execute("SELECT min(at) FROM heartbeats WHERE loop = 'boot'").fetchone()[0]
    loops, retired = {}, []
    last_boot = parse_ts(conn.execute("SELECT max(at) FROM heartbeats WHERE loop = 'boot'").fetchone()[0])
    for row in conn.execute("""SELECT loop, max(at) AS last_at, (SELECT ok FROM heartbeats h WHERE h.loop = x.loop ORDER BY id DESC LIMIT 1) AS last_ok,
                               (SELECT max(at) FROM heartbeats h WHERE h.loop = x.loop AND h.ok = 1) AS last_ok_at
                               FROM heartbeats x WHERE loop NOT IN ('boot', 'pause') GROUP BY loop"""):
        # a CT log not polled at all since this process started (left the log list, or renamed: "ct:skylight" before the per-shard names) is retired, not degraded
        if (
            row["loop"].startswith("ct:")
            and last_boot
            and parse_ts(row["last_at"]) < last_boot
            and (now - last_boot).total_seconds() > _stale_limit(row["loop"], conf)
        ):
            retired.append(row["loop"])
            continue
        age = (now - parse_ts(row["last_ok_at"])).total_seconds() if row["last_ok_at"] else None
        status = (
            "ok"
            if row["last_ok"] and age is not None and age <= _stale_limit(row["loop"], conf)
            else ("error" if not row["last_ok"] else "stale")
        )
        loops[row["loop"]] = {
            "last_ok_at": row["last_ok_at"],
            "status": status,
            "age_s": None if age is None else int(age),
        }
    queued = conn.execute("SELECT count(*), min(created_at) FROM jobs WHERE status = 'queued'").fetchone()
    due = conn.execute(
        "SELECT min(created_at) FROM jobs WHERE status = 'queued' AND (run_after IS NULL OR run_after <= ?)",
        (iso(now),),
    ).fetchone()[0]  # 24 h rechecks wait on purpose
    oldest = parse_ts(due)
    where = "data_mode = 'LIVE' AND found_by != 'baseline'"  # baseline and DEMO rows never count
    reviewed = FIND_BANDS.format(alias="domains")  # a find is only what an analyst would look at: GRAY / FURTHER
    counters = {
        "certs_checked": conn.execute("SELECT COALESCE(sum(entries), 0) FROM heartbeats").fetchone()[0],
        "finds": conn.execute(
            f"SELECT count(*) FROM domains WHERE {where} AND found_by != 'feeds' AND {reviewed}"
        ).fetchone()[0],
        "list_echoes": conn.execute(f"SELECT count(*) FROM domains WHERE {where} AND found_by = 'feeds'").fetchone()[0],
    }
    last_entry = conn.execute("SELECT max(at) FROM heartbeats WHERE loop LIKE 'ct:%' AND ok = 1").fetchone()[0]
    worker_age = loops.get("worker", {}).get("age_s")
    ct_ages = [loop["age_s"] for name, loop in loops.items() if name.startswith("ct:") and loop["age_s"] is not None]
    return {
        "mode": "LIVE" if os.environ.get("SCAMSHIELD_LIVE") else "DEV",
        "started_at": boot,
        "server_time": iso(now),
        "loops": loops,
        "retired_loops": retired,
        "queue": {
            "queued": queued[0],
            "running": conn.execute("SELECT count(*) FROM jobs WHERE status = 'running'").fetchone()[0],
            "oldest_queued_s": int((now - oldest).total_seconds()) if oldest else None,
        },
        "worker_age_s": worker_age,
        "ct_age_s": min(ct_ages, default=None),
        "counters": counters,
        "last_entry_s": int((now - parse_ts(last_entry)).total_seconds()) if last_entry else None,
        "banner": _banner(conn, boot, loops, now, conf) if os.environ.get("SCAMSHIELD_LIVE") else None,
    }


def _gst(moment: datetime) -> str:
    return moment.astimezone(_GST).strftime("%a %H:%M GST")


def _banner(conn, boot, loops, now, conf) -> dict:
    ok_ages = [loop["age_s"] for loop in loops.values() if loop["age_s"] is not None]
    if loops and min(ok_ages, default=10**9) > conf["offline_after_s"]:
        last = conn.execute("SELECT max(at) FROM heartbeats WHERE ok = 1").fetchone()[0]
        return {
            "state": "red",
            "text": f"OFFLINE · no source answered for {conf['offline_after_s'] // 60} min — showing data found before {_gst(parse_ts(last))}",
        }
    degraded = sum(1 for loop in loops.values() if loop["status"] != "ok")
    since = parse_ts(boot)
    running = (
        f"since {_gst(since)} ({int((now - since).total_seconds() // 3600)} h {int((now - since).total_seconds() % 3600 // 60)} min)"
        if since
        else "just started"
    )
    if degraded:
        return {"state": "amber", "text": f"LIVE · {degraded} source{'s' if degraded > 1 else ''} degraded · {running}"}
    return {"state": "green", "text": f"LIVE · {running}"}
