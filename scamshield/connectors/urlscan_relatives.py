"""Find relatives (idea 4): other sites of the same kit, found through the case's own urlscan scan.

A link here means the same operator's kit, never just the same brand: only a shared script / style file (SHA-256), a WebSocket
panel host or a rare page IP is searched. The official favicon is deliberately not used (it says "same brand", not "same gang").
Found domains are only queued for a normal check with a `relative_link` fact; nothing is marked scam. Every failure comes back as data.
Everything taken from a scanned page (hosts, file names, hashes) is attacker-controlled: validated before it goes into a query, clipped before it is stored."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from urllib.parse import quote, urlsplit

from scamshield import db, intake, sources
from scamshield.connectors.tavily_search import _is_benign, _is_official
from scamshield.contracts import Ctx, Fact
from scamshield.netsafe import registrable_of

SOURCE = "urlscan_relatives"  # budget name; facts carry the data source "urlscan"
FACT_SOURCE = "urlscan"
FOUND_BY = "relatives"
CLIP = 80  # longest attacker-chosen string (file name, host) kept in a reason, message or fact
_SHA = re.compile(r"^[0-9a-f]{64}$")
_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,62})(?:\.[a-z0-9](?:[a-z0-9-]{0,62}))+$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_RESULT_UUID = re.compile(r"/result/([0-9a-f-]{36})/?")
log = logging.getLogger(__name__)


def _clip(text, limit: int = CLIP) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def valid_host(host: str) -> bool:
    return bool(_HOST.fullmatch(host or ""))


def _ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value or "")))
    except ValueError:
        return None


def _load(conn, fqdn: str) -> dict | None:
    """The case's id and state, its newest urlscan scan (from a urlscan_hit fact) and its own resolved IPs (fallback when urlscan never scanned it)."""
    row = conn.execute("SELECT id, state FROM domains WHERE fqdn = ?", (fqdn,)).fetchone()
    if row is None:
        return None
    uuid, ips = None, []
    for fact in db.current_facts(conn, row[0]):
        value = json.loads(fact["value_json"]) if fact["status"] == "ok" else {}
        found = _RESULT_UUID.search(str(value.get("result_url") or "")) if fact["type"] == "urlscan_hit" else None
        if found and _UUID.fullmatch(found.group(1)):
            uuid = found.group(1)  # facts come oldest first: the newest scan wins
        elif fact["type"] == "dns_a":
            ips = [str(ip) for ip in value.get("records", [])]
    return {"id": row[0], "state": row[1], "uuid": uuid, "ips": ips}


def _shared_ip(ip: str, asn, shared: dict) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    number = str(asn or "").upper().removeprefix("AS")
    return (
        (not address.is_global)
        or (number.isdigit() and int(number) in shared["asns"])
        or any(address in ipaddress.ip_network(c) for c in shared["cidrs"])
    )


def _shared_host(host: str, ctx: Ctx) -> bool:
    shared = (
        ctx.settings.shared_infra["host_suffixes"] + ctx.settings.scoring["snapshot"]["exfil_hosts"]
    )  # Telegram / Slack: shared by everyone, not a panel
    return any(host == s or host.endswith(f".{s}") for s in shared) or _is_benign(
        host, ctx.settings.sources["tavily"].extra["benign_domains"]
    )


def signals(result: dict, ctx: Ctx) -> list[dict]:
    """What to search, strongest first: WebSocket panel hosts, the page's own scripts, a rare page IP, its own styles, then scripts / styles
    from other hosts (feature script_3p: a medium link at most, a third-party file says less about the operator)."""
    page = result.get("page") or {}
    own = registrable_of(str(page.get("domain") or "").lower())
    panels, scripts, styles, other = [], [], [], []
    for item in (result.get("data") or {}).get("requests") or []:
        request = (item or {}).get("request") or {}
        url = str((request.get("request") or {}).get("url") or "")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        sha = str(((item or {}).get("response") or {}).get("hash") or "").lower()
        if not valid_host(host):
            continue  # also stops a host such as `a" OR domain:"x` from reaching a query
        if url.startswith(("ws://", "wss://")) or request.get("type") == "WebSocket":
            if registrable_of(host) != own and not _shared_host(host, ctx):
                panels.append({"feature": "panel", "value": host, "file": _clip(host), "query": f'domain:"{host}"'})
        elif (
            request.get("type") in ("Script", "Stylesheet") and _SHA.fullmatch(sha) and "/cdn-cgi/" not in parts.path
        ):  # Cloudflare's own scripts on every site
            file = _clip(parts.path.rstrip("/").rsplit("/", 1)[-1] or host)
            if registrable_of(host) == own:
                (scripts if request["type"] == "Script" else styles).append(
                    {"feature": "script", "value": sha, "file": file, "query": f'hash:"{sha}"'}
                )
            else:
                other.append({"feature": "script_3p", "value": sha, "file": file, "query": f'hash:"{sha}"'})
    ip = _ip(page.get("ip"))
    rare_ip = (
        []
        if not ip or _shared_ip(ip, page.get("asn"), ctx.settings.shared_infra)
        else [{"feature": "ip", "value": ip, "file": ip, "query": f'page.ip:"{ip}"'}]
    )
    seen, ordered = set(), []
    for signal in [*panels, *scripts, *rare_ip, *styles, *other]:
        if signal["value"] not in seen:
            seen.add(signal["value"])
            ordered.append(signal)
    return ordered


def _reason(signal: dict, origin: str) -> str:
    what = {
        "script": f"same {signal['file']}",
        "script_3p": f"same third-party {signal['file']}",
        "panel": f"same data panel {signal['file']}",
        "ip": f"same IP {signal['value']}",
    }[signal["feature"]]
    return f"found via relative: {what} as {origin}"


async def _search(ctx: Ctx, cfg: dict, key: str, query: str) -> dict | sources.SourceError:
    payload = await sources.fetch_json(
        ctx, SOURCE, f"{cfg['search_url']}?q={quote(query)}&size={cfg['size']}", {"api-key": key}
    )
    if isinstance(payload, sources.SourceError):
        return payload
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        return sources.SourceError(SOURCE, "bad_payload")
    return payload


def _distinct_sites(results: list) -> int:
    """How many different registrable domains the returned scans are on: a kit file reused by one gang sits on tens of its own domains,
    a library on hundreds of unrelated ones (a gang main.js = 61 scans on 46 domains)."""
    return len(
        {registrable_of(str(((r or {}).get("page") or {}).get("domain") or "").lower()) for r in results} - {None, ""}
    )


def _hosts(results: list, origin: str, ctx: Ctx) -> dict[str, dict]:
    """Newest scan per host, without the case itself, official / benign / platform hosts, bare IPs and anything that is not a clean hostname."""
    newest: dict[str, dict] = {}
    for item in results:
        page, task = (item or {}).get("page") or {}, (item or {}).get("task") or {}
        host = str(page.get("domain") or "").lower()
        if (
            not valid_host(host)
            or _ip(host)
            or not _UUID.fullmatch(str(task.get("uuid") or ""))
            or registrable_of(host) == registrable_of(origin)
            or _is_official(host, ctx.settings.brands)
            or _shared_host(host, ctx)
        ):
            continue
        if host not in newest or str(task.get("time") or "") > str((newest[host].get("task") or {}).get("time") or ""):
            newest[host] = item
    return newest


def _known(conn, hosts: list[str]) -> dict[str, int]:
    rows = (
        conn.execute(f"SELECT fqdn, id FROM domains WHERE fqdn IN ({','.join('?' * len(hosts))})", hosts).fetchall()
        if hosts
        else []
    )
    return {r[0]: r[1] for r in rows}


def _store_facts(conn, domain_id: int, facts: list[Fact]) -> None:
    """Facts on a domain already in our database, without queueing it again (intake would re-check it)."""
    for fact in facts:
        value_json = json.dumps(fact.value)
        if (
            fact.type == "relative_link"
            and conn.execute(
                "SELECT 1 FROM facts WHERE domain_id = ? AND type = ? AND value_json = ?",
                (domain_id, fact.type, value_json),
            ).fetchone()
        ):
            continue
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, observed_at, fetched_at, status, error, data_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                domain_id,
                fact.type,
                value_json,
                fact.source,
                fact.observed_at,
                fact.fetched_at,
                fact.status,
                fact.error,
                fact.data_mode,
            ),
        )
    conn.commit()


def _store_run(conn, fqdn: str, out: dict, now: str) -> None:
    """The click's outcome on the case, shown next to the button (newest wins)."""
    row = conn.execute("SELECT id FROM domains WHERE fqdn = ?", (fqdn,)).fetchone()
    if row:
        value = {
            "message": out["message"],
            "queued": out["queued"],
            "linked": out["linked"],
            "searched": out["searched"],
            "error": out["error"],
        }
        _store_facts(conn, row[0], [Fact("relatives_run", value, FACT_SOURCE, now, now, "ok")])


def _error_text(reason: str, cfg) -> str:
    if reason == "budget":
        return (
            f"Daily limit for relative search used ({cfg.budget_per_day} urlscan requests a day) — try again tomorrow"
        )
    return f"urlscan unavailable right now ({sources.reason_text(reason)}) — try again later"


def _empty() -> dict:
    return {"queued": [], "linked": [], "searched": [], "skipped": [], "error": None, "message": ""}


async def _link(ctx: Ctx, signal: dict, hosts: dict[str, dict], fqdn: str, now: str, out: dict, cap: int) -> int:
    """Queue new hosts (at most `cap` per click) and only add the link fact to hosts we already have. Returns how many hosts got the link."""
    known = await db.run(_known, sorted(hosts))
    linked = 0
    for host, item in sorted(hosts.items()):
        task = item.get("task") or {}
        when = _clip(task.get("time"), 40) or None
        value = {
            "feature": signal["feature"],
            "value": signal["value"],
            "file": signal["file"],
            "origin": fqdn,
            "reason": _reason(signal, fqdn),
            "scan_date": when,
            "result_url": f"https://urlscan.io/result/{task['uuid']}/",
        }
        fact = Fact("relative_link", value, FACT_SOURCE, when, now, "ok")
        if host in known:
            await db.run(_store_facts, known[host], [fact])
            out["linked"] += [host] if host not in out["linked"] else []
        elif len(out["queued"]) < cap:
            await intake.submit(host, FOUND_BY, [fact], 0)
            out["queued"].append(host)
        else:
            continue
        linked += 1
    return linked


async def _find(ctx: Ctx, fqdn: str) -> dict:
    cfg = ctx.settings.sources[SOURCE]
    extra, now = cfg.extra, ctx.now()
    out = _empty()
    if not valid_host(fqdn):
        return {**out, "error": "unknown", "message": "Not a domain name"}
    case = await db.run(_load, fqdn)
    if case is None:
        return {**out, "error": "unknown", "message": "Unknown domain"}
    if case["state"] == "OFFICIAL" or _is_official(fqdn, ctx.settings.brands):
        return {**out, "error": "official", "message": "Official domain — relatives are not searched"}
    key = ctx.settings.secrets.get(cfg.key_env or "")
    if not key:
        return {**out, "error": "no_key", "message": "urlscan unavailable: no API key set"}
    left = extra["max_queries_per_click"]  # every urlscan request of this click: scan lookup, scan read and searches
    scan_time, scan_url, found_signals = None, None, []
    uuid = case["uuid"]
    if uuid is None:  # urlscan may have scanned it without our brand search noticing
        lookup = await _search(ctx, extra, key, f'page.domain:"{fqdn}"')
        left -= 1
        if isinstance(lookup, sources.SourceError):
            out["error"] = lookup.reason
        else:
            own = [
                r
                for r in lookup["results"]
                if str(((r or {}).get("page") or {}).get("domain") or "").lower() == fqdn
                and _UUID.fullmatch(str(((r or {}).get("task") or {}).get("uuid") or ""))
            ]
            uuid = max(own, key=lambda r: str(r["task"].get("time") or ""))["task"]["uuid"] if own else None
    if uuid and not out["error"] and left > 0:
        result = await sources.fetch_json(ctx, SOURCE, f"{extra['result_url']}{uuid}/", {"api-key": key})
        left -= 1
        if isinstance(result, sources.SourceError):
            out["error"] = result.reason
        elif isinstance(result, dict):
            found_signals = signals(result, ctx)
            scan_time = _clip((result.get("task") or {}).get("time"), 40) or None
            scan_url = f"https://urlscan.io/result/{uuid}/"
    if not uuid and not out["error"]:  # no scan at all: our own DNS answer still gives the page IP
        found_signals = [
            {"feature": "ip", "value": _ip(ip), "file": _ip(ip), "query": f'page.ip:"{_ip(ip)}"'}
            for ip in case["ips"]
            if _ip(ip) and not _shared_ip(ip, None, ctx.settings.shared_infra)
        ][:1]
    origin_facts = []
    for signal in found_signals:
        if out["error"] or left <= 0:
            break
        answer = await _search(ctx, extra, key, signal["query"])
        left -= 1
        if isinstance(answer, sources.SourceError):
            out["error"] = answer.reason
            break
        out["searched"].append(signal["file"])
        results = answer["results"]
        sites = _distinct_sites(results)
        if sites >= extra["popular_max"]:
            total = answer.get("total") if isinstance(answer.get("total"), int) else len(results)
            out["skipped"].append(f"{signal['file']} — common library / shared host, on {sites}+ sites ({total} scans)")
            continue
        hosts = _hosts(results, fqdn, ctx)
        linked = await _link(ctx, signal, hosts, fqdn, now, out, extra["max_queued_per_click"])
        if linked:
            origin_facts.append(
                Fact(
                    "relative_link",
                    {
                        "feature": signal["feature"],
                        "value": signal["value"],
                        "file": signal["file"],
                        "origin": fqdn,
                        "reason": f"searched urlscan: same {signal['file']} on {linked} other site(s)",
                        "scan_date": scan_time,
                        "result_url": scan_url,
                    },
                    FACT_SOURCE,
                    scan_time,
                    now,
                    "ok",
                )
            )
    if out["error"]:
        out["message"] = _error_text(out["error"], cfg) + (
            f"; {len(out['queued'])} sites queued before it stopped" if out["queued"] else ""
        )
    elif not found_signals:
        out["message"] = "urlscan has no scan of this site with scripts, a panel or a rare IP — nothing to search"
    else:
        found = len(out["queued"]) + len(out["linked"])
        out["message"] = f"Searched urlscan {len(out['searched'])} time(s): " + (
            f"{len(out['queued'])} sites queued for a check"
            + (f", {len(out['linked'])} already known linked" if out["linked"] else "")
            if found
            else "no relatives found"
        )
        if out["skipped"]:
            out["message"] += "; skipped " + "; ".join(out["skipped"])
    await db.run(_store_facts, case["id"], origin_facts)
    return out


async def find(ctx: Ctx, fqdn: str) -> dict:
    """Analyst click "Find relatives". Never raises: any failure is the friendly "urlscan unavailable" message."""
    now = ctx.now()
    try:
        out = await _find(ctx, fqdn)
    except Exception:  # the card must always answer
        log.exception("find relatives failed for %s", _clip(fqdn))
        out = {
            **_empty(),
            "error": "exception",
            "message": "urlscan unavailable right now (unexpected error) — try again later",
        }
    try:
        await db.run(_store_run, fqdn, out, now)
    except Exception:  # storing the outcome is best effort
        log.exception("could not store the find-relatives outcome for %s", _clip(fqdn))
    return out
