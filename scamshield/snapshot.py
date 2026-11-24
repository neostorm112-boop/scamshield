"""Safe page snapshot (ADR 0004): the browser runs in a subprocess killed after hard_kill_s; this module checks the link first,
turns the page into facts (title, text, form fields, brand shown on a non-official domain) and stores them."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from scamshield import db, graph, netsafe, runtime, triage_ai, worker
from scamshield.config import CONFIG_DIR
from scamshield.contracts import Rejection, SnapshotResult
from scamshield.netsafe import registrable_of
from scamshield.scoring import page_brand_names

REFS_PATH = CONFIG_DIR / "brand_refs.json"
_BROWSER = asyncio.Semaphore(
    1
)  # analyst clicks: one at a time, never queued behind the automatic ones, which are limited by snapshot.concurrency (ADR 0004)
_ASKS = {
    "card": r"card.?(number|no)|cc.?num|ccnum|cc-number|\bpan\b|رقم البطاقة",
    "cvv": r"cvv|cvc|cc-csc|security.?code|رمز الأمان",
    "otp": r"otp|one.?time|verification.?code|sms.?code|passcode|رمز التحقق",
    "emirates_id": r"emirates.?id|\beid\b|784-|الهوية",
    "password": r"password|passwd|كلمة المرور",
}


def classify_asks(fields: list[dict]) -> list[str]:
    """What the form asks for, from field names, types, labels (names only, never values)."""
    found = []
    for kind, pattern in _ASKS.items():
        if any(
            re.search(pattern, f"{f.get('name', '')} {f.get('label', '')} {f.get('autocomplete', '')}".lower())
            or (kind == "password" and f.get("type") == "password")
            for f in fields
        ):
            found.append(kind)
    return found


def usable_hash(h: str | None) -> str | None:
    """A near-empty picture (plain or transparent: almost all bits equal) matches every other empty picture, so it is no evidence."""
    return h if h and 8 <= int(h, 16).bit_count() <= 56 else None


def _hash_distance(a: str | None, b: str | None) -> int | None:
    a, b = usable_hash(a), usable_hash(b)
    return None if not a or not b else (int(a, 16) ^ int(b, 16)).bit_count()


def brand_shown(title: str, text: str, hashes: dict, final_host: str, brands, refs: dict, cfg: dict) -> dict | None:
    """Which brand the page shows (name in title/text, logo / page picture close to the official site's, same favicon), or None for an official host."""
    best = None
    for brand in brands:
        if any(final_host == d or final_host.endswith(f".{d}") for d in brand.official_domains):
            return None
        hits = page_brand_names(
            title, text, [final_host], brand, cfg
        )  # the page's own address is cut out: a host name is no brand shown
        via = ["name"] if hits else []
        for ref in refs.get(brand.id, []):
            d_logo, d_page = (
                _hash_distance(hashes.get("logo"), ref.get("logo")),
                _hash_distance(hashes.get("page"), ref.get("page")),
            )
            via += (
                (["logo"] if d_logo is not None and d_logo <= cfg["logo_max_distance"] else [])
                + (["page"] if d_page is not None and d_page <= cfg["page_max_distance"] else [])
                + (["favicon"] if hashes.get("favicon") and hashes["favicon"] == ref.get("favicon") else [])
            )
        via = sorted(set(via))
        if via == ["page"] or via == [
            "name",
            "page",
        ]:  # two mostly-white pages look alike: the page picture only backs up a logo or favicon match
            via.remove("page")
        if via and (best is None or len(via) > len(best["via"])):
            best = {"brand": brand.id, "via": via}
    return best


def _refs() -> dict:
    try:
        return json.loads(REFS_PATH.read_text(encoding="utf-8")).get("brands", {})
    except (OSError, ValueError):
        return {}  # no reference file yet: only names can match


def _message(result: SnapshotResult, limit: int) -> str | None:
    if result.status == "timeout":
        return f"Snapshot not taken: page did not load in {limit} s."
    if result.status == "blocked":
        return f"Snapshot stopped for safety: {result.reason}."
    if result.status == "error":
        return (
            f"Snapshot not saved: {result.reason}."
            if result.reason == "disk almost full"
            else f"Snapshot not taken: page did not load in {limit} s."
        )
    return None


async def _run_runner(job: dict, kill_s: int) -> SnapshotResult:
    proc = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "scamshield.snapshot_runner",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(json.dumps(job).encode()), kill_s)
        data = json.loads(out.decode().strip().splitlines()[-1])
    except TimeoutError:
        data = {"status": "timeout", "reason": f"killed after {kill_s} s"}
    except (ValueError, IndexError):
        data = {"status": "error", "reason": "browser crashed"}
    finally:
        if proc.returncode is None:
            os.killpg(proc.pid, signal.SIGKILL)  # the whole process group: Chromium and its helpers
            await proc.wait()
    return SnapshotResult(
        data["status"],
        data.get("reason"),
        data.get("final_url"),
        data.get("redirect_chain", []),
        data.get("title"),
        data.get("visible_text", ""),
        data.get("form_fields", []),
        data.get("screenshot_path"),
        None,
        data.get("bytes_received", 0),
        {**data.get("hashes", {}), "favicon_b64": data.get("favicon")},
        data.get("disabled", []),
        data.get("parked"),
        data.get("exfil", []),
        data.get("hotlinks", []),
    )


async def capture(
    url: str,
    settings,
    out_dir: Path,
    check=netsafe.check_url,
    fake_dns: dict | None = None,
    max_bytes: int | None = None,
    max_requests: int | None = None,
    auto: bool = False,
) -> SnapshotResult:
    """Never raises: a failure is a SnapshotResult with status blocked / timeout / error. `check` and `fake_dns` are test seams for local pages; `max_bytes` / `max_requests` are raised only for the official sites in build_brand_refs."""
    cfg = settings.sources["snapshot"].extra
    out_dir.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(out_dir).free < cfg["min_free_gb"] * 2**30:
        return SnapshotResult("error", "disk almost full", None, [], None, "", [], None, None, 0)
    checked = await check(url)
    if isinstance(checked, Rejection):
        return SnapshotResult(
            "blocked",
            "private address blocked" if checked.code in ("PRIVATE_ADDRESS", "LOCALHOST") else checked.message,
            None,
            [],
            None,
            "",
            [],
            None,
            None,
            0,
        )
    job = {
        "url": checked.url,
        "out_dir": str(out_dir),
        "fake_dns": fake_dns or {},
        "nav_timeout_ms": cfg["nav_timeout_s"] * 1000,
        "max_bytes": max_bytes or cfg["max_bytes"],
        "max_requests": max_requests or cfg["max_requests"],
        "max_redirects": cfg["max_redirects"],
        "hard_kill_s": cfg["hard_kill_s"],
        "exfil_hosts": settings.scoring["snapshot"]["exfil_hosts"],
        "official_domains": [d for b in settings.brands for d in b.official_domains],
    }
    async with (
        contextlib.nullcontext() if auto else _BROWSER
    ):  # automatic: the caller already limits how many run at once
        started = asyncio.get_running_loop().time()
        result = await _run_runner(job, cfg["hard_kill_s"])
        quick = (
            asyncio.get_running_loop().time() - started < cfg["nav_timeout_s"] / 2
        )  # a slow failure is not retried: the analyst is waiting
        if (
            result.status == "error"
            and quick
            and checked.url.startswith("https://")
            and re.search(r"ERR_SSL|ERR_CERT", result.reason or "")
        ):
            result = await _run_runner(
                {**job, "url": "http://" + checked.url[len("https://") :].replace(":443/", "/", 1)}, cfg["hard_kill_s"]
            )  # broken TLS: kits often serve plain http (s3wa.top)
    favicon = result.hashes.pop("favicon_b64", None)
    result.hashes["favicon"] = hashlib.sha256(base64.b64decode(favicon)).hexdigest() if favicon else None
    return result


def _store(conn, domain_id: int, fqdn: str, result: SnapshotResult, settings, limit: int) -> None:
    stamp = worker._now()

    def fact(kind, value, status="ok", error=None):
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, error) VALUES (?, ?, ?, 'snapshot', ?, ?, ?, ?)",
            (domain_id, kind, json.dumps(value), stamp, stamp, status, error),
        )

    message = _message(result, limit)
    seen = {
        **({"exfil": result.exfil} if result.exfil else {}),
        **({"hotlinks": result.hotlinks} if result.hotlinks else {}),
    }  # kept even when the snapshot failed: a leak attempt is never lost
    if result.status == "blocked":
        fact("snapshot_blocked", {"reason": result.reason, "message": message, **seen})
    elif message:
        fact("snapshot_page", seen, "error", message)
    else:
        artifact = None
        if result.screenshot_path:
            data = Path(result.screenshot_path).read_bytes()
            artifact = conn.execute(
                "INSERT INTO artifacts (domain_id, kind, path, sha256, bytes, captured_at) VALUES (?, 'screenshot', ?, ?, ?, ?) RETURNING id",
                (domain_id, result.screenshot_path, hashlib.sha256(data).hexdigest(), len(data), stamp),
            ).fetchone()[0]
        fact(
            "snapshot_page",
            {
                "title": result.title,
                "final_url": result.final_url,
                "redirects": result.redirect_chain,
                "text": result.visible_text,
                "artifact_id": artifact,
                **({"disabled": result.disabled} if result.disabled else {}),
                **({"parked": result.parked} if result.parked else {}),
                **seen,
            },
        )
        fact(
            "snapshot_form", {"fields": result.form_fields, "asks": classify_asks(result.form_fields)}
        )  # always written: the newest row per type wins, so an empty one clears an older answer
        host = registrable_of(urlsplit(result.final_url or f"https://{fqdn}").hostname or fqdn)
        shown = brand_shown(
            result.title or "",
            result.visible_text,
            result.hashes,
            host,
            settings.brands,
            _refs(),
            settings.scoring["snapshot"],
        )
        fact("snapshot_brand", shown or {})
        if shown and shown["via"] != ["name"]:  # a name in the text alone is too weak to label the domain for good
            conn.execute(
                "UPDATE domains SET brand_id = COALESCE(brand_id, ?) WHERE id = ?", (shown["brand"], domain_id)
            )
    worker._reassess(conn, domain_id, fqdn, settings, stamp)
    conn.commit()
    reassessed = [fqdn]
    if (
        result.status == "ok" and not message and result.parked
    ):  # its neighbours on the same parking IP may now drop to GRAY_LOW (scoring parked_peers)
        peers = [
            (pid, peer)
            for pid, peer in graph.unsnapshotted_ip_peers(conn, fqdn, settings.scoring, settings.shared_infra)
            if (
                conn.execute(
                    "SELECT json_extract(components_json, '$.band') FROM assessments WHERE domain_id = ? ORDER BY id DESC LIMIT 1",
                    (pid,),
                ).fetchone()
                or [None]
            )[0]
            != "GRAY_LOW"
        ]
        # each re-assessment loads the graph (seconds on a big DB): already-lowered peers are skipped and the rest capped; the others follow on their own re-check
        for peer_id, peer in peers[: settings.scoring["snapshot"]["parked_peers_reassess_max"]]:
            worker._reassess(conn, peer_id, peer, settings, stamp)
            conn.commit()  # one short write per peer: a parking farm has 100+ peers, one transaction held the write lock ~25 s ("database is locked")
            reassessed.append(peer)
    return reassessed


async def take(
    settings, fqdn: str, check=netsafe.check_url, fake_dns: dict | None = None, auto: bool = False
) -> SnapshotResult | None:
    """Snapshot one known domain and store the facts; None when the domain is unknown."""

    def lookup(conn):
        row = conn.execute("SELECT id FROM domains WHERE fqdn = ?", (fqdn,)).fetchone()
        url = (
            conn.execute("SELECT url FROM urls WHERE domain_id = ? ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
            if row
            else None
        )
        return (row["id"], url["url"] if url else f"https://{fqdn}/") if row else None

    found = await db.run(lookup)
    if found is None:
        return None
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    result = await capture(
        found[1],
        settings,
        Path(settings.evidence_dir) / fqdn / stamp,
        check,
        fake_dns,
        **({"auto": True} if auto else {}),
    )
    for name in await db.run(
        _store, found[0], fqdn, result, settings, settings.sources["snapshot"].extra["nav_timeout_s"]
    ):
        triage_ai.auto_in_background(name)  # each new assessment is judged once if gray, within the judge's caps
    return result


_QUEUED = """d.state = 'REVIEW' AND a.flags_json LIKE '%"GRAY%' AND NOT EXISTS (SELECT 1 FROM feedback WHERE domain_id = d.id)
    AND EXISTS (SELECT 1 FROM facts WHERE domain_id = d.id AND type IN ('dns_a', 'dns_aaaa') AND status = 'ok')"""  # queued GRAY / GRAY_LOW, no analyst decision, resolves
_LAST_ASSESSMENT = "JOIN assessments a ON a.id = (SELECT MAX(id) FROM assessments WHERE domain_id = d.id)"


_FIXED_BLOCKS = (
    "PRIVATE_ADDRESS",
    "LOCALHOST",
    "BAD_PORT",
    "BAD_SCHEME",
    "NOT_A_URL",
)  # the safety check would refuse again: no point re-trying


def _due_resnap(conn, hours: list[float], now: datetime, skip=()) -> str | None:
    """Queued domain whose newest snapshot was empty and whose next re-snapshot is due: n-th snapshot taken, wait hours[n-1] after it; none after the last step.
    Empty = failed, blocked (not by a fixed safety rule), a parked ad page, or a blank page: kits are often uploaded 6-48 h after the certificate."""
    if not hours:
        return None
    rows = conn.execute(
        f"""SELECT fqdn, fetched_at, n FROM (
            SELECT d.fqdn, f.fetched_at, f.type, f.status, f.value_json,
                   (SELECT COUNT(*) FROM facts WHERE domain_id = d.id AND type IN ('snapshot_page', 'snapshot_blocked')) AS n
            FROM domains d {_LAST_ASSESSMENT}
            JOIN facts f ON f.id = (SELECT MAX(id) FROM facts WHERE domain_id = d.id AND type IN ('snapshot_page', 'snapshot_blocked'))
            WHERE {_QUEUED})
        WHERE n <= ? AND json_valid(value_json) AND (
              (type = 'snapshot_blocked' AND COALESCE(json_extract(value_json, '$.reason'), '') NOT IN ({",".join("?" * len(_FIXED_BLOCKS))}))
           OR (type = 'snapshot_page' AND (status != 'ok' OR json_extract(value_json, '$.parked') IS NOT NULL
               OR TRIM(COALESCE(json_extract(value_json, '$.title'), '') || COALESCE(json_extract(value_json, '$.text'), '')) = '')))""",
        (len(hours), *_FIXED_BLOCKS),
    ).fetchall()
    due = []
    for row in rows:
        try:
            ready = datetime.fromisoformat(row["fetched_at"]) + timedelta(hours=hours[row["n"] - 1])
            if ready <= now and row["fqdn"] not in skip:
                due.append((ready, row["fqdn"]))
        except (TypeError, ValueError, IndexError):
            continue  # an unreadable time is skipped, never raised
    return min(due)[1] if due else None


def _next_generic(conn, skip=()) -> str | None:
    """Newest never-snapshotted brandless (generic CT / NRD name) domain still in the queue: without a share of the budget they never get a turn (0 of them snapshotted)."""
    row = conn.execute(
        f"""SELECT d.fqdn FROM domains d {_LAST_ASSESSMENT}
        WHERE {_QUEUED} AND NOT EXISTS (SELECT 1 FROM facts WHERE domain_id = d.id AND type LIKE 'snapshot\\_%' ESCAPE '\\')
          AND EXISTS (SELECT 1 FROM facts WHERE domain_id = d.id AND type = 'lookalike' AND json_extract(value_json, '$.method') = 'generic_name')
          AND d.fqdn NOT IN ({",".join("?" * len(skip))})
        ORDER BY d.first_seen_at DESC LIMIT 1""",
        tuple(skip),
    ).fetchone()
    return row["fqdn"] if row else None


_claims = {"n": 0}  # automatic claims in this process: every generic_every-th one tries a brandless domain first


def _next_auto(conn, resnap_hours=(), now: datetime | None = None, skip=()) -> str | None:
    """Next automatic snapshot: a never-snapshotted GRAY domain, then a due re-snapshot of an empty / parked page, then a never-snapshotted GRAY_LOW one.
    `skip`: domains being snapshotted right now. Newest first within a tier, brandless (generic CT) names after UAE brand hits; no analyst decision, still resolving. A failed first snapshot counts as empty and is retried on the re-snapshot schedule."""

    def fresh(low: bool) -> str | None:
        row = conn.execute(
            f"""SELECT d.fqdn FROM domains d {_LAST_ASSESSMENT}
            WHERE {_QUEUED} AND NOT EXISTS (SELECT 1 FROM facts WHERE domain_id = d.id AND type LIKE 'snapshot\\_%' ESCAPE '\\')
              AND {"" if low else "NOT"} a.flags_json LIKE '%"GRAY_LOW"%' AND d.fqdn NOT IN ({",".join("?" * len(skip))})
            ORDER BY EXISTS (SELECT 1 FROM facts WHERE domain_id = d.id AND type = 'lookalike' AND json_extract(value_json, '$.method') = 'generic_name'), d.first_seen_at DESC LIMIT 1""",
            tuple(skip),
        ).fetchone()
        return row["fqdn"] if row else None

    return fresh(False) or _due_resnap(conn, list(resnap_hours), now or datetime.now(UTC), skip) or fresh(True)


async def claim_auto(settings, running: set[str]) -> str | None:
    """Pick the next automatic domain that is not being snapshotted now and spend one unit of the hourly budget; the caller must run it and then discard it from `running`.
    Picks must not overlap (the monitor claims one at a time), or two workers could take the same domain."""
    _claims["n"] += 1
    every = settings.sources["snapshot"].extra.get("generic_every", 0)
    fqdn = await db.run(_next_generic, tuple(running)) if every and _claims["n"] % every == 0 else None
    fqdn = fqdn or await db.run(
        _next_auto, settings.sources["snapshot"].extra.get("resnap_hours", []), None, tuple(running)
    )
    if fqdn is None or not await runtime.DbBudget(settings).take("snapshot", "auto"):
        return None
    running.add(fqdn)
    return fqdn


async def run_claimed(settings, fqdn: str, running: set[str], **seams) -> None:
    try:
        await take(settings, fqdn, auto=True, **seams)
    finally:
        running.discard(fqdn)


async def auto_once(settings, **seams) -> str | None:
    """One automatic snapshot if the hourly budget allows; returns the fqdn or None (nothing queued / budget used up)."""
    running: set[str] = set()
    fqdn = await claim_auto(settings, running)
    if fqdn:
        await run_claimed(settings, fqdn, running, **seams)
    return fqdn
