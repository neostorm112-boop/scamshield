"""View models of the one-screen workspace : queue rows and a case read as steps. Real data only; unknown stays unknown."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime

from scamshield import config, db, explain, graph, live, triage_ai
from scamshield import sources as source_text
from scamshield.scoring import _CHECKS, _FEED_NAMES, _offers_work_via_messenger

GST_NAME = {"scam": "Confirmed scam (analyst)", "legit": "Legit (analyst)", "unclear": "Unclear (analyst)"}
_CHECK_NAMES = {
    "dns": "website address",
    "asn": "hosting company",
    "age": "registration date",
    "certs": "security certificates",
    "feed": "phishing lists",
}
_SRC = {
    "feed_match": "Phishing list",
    "rdap": "Domain registry",
    "dns": "Address lookup",
    "asn": "Hosting lookup",
    "certspotter": "Certificate search",
    "tavily": "Web search",
    "urlhaus": "URLhaus",
    "urlscan": "urlscan",
    "lookalike": "Brand check",
    "brand_check": "Brand check",
    "baseline": "Brand check",
    "snapshot": "Snapshot",
}
_ASKS = {
    "card": "card number",
    "cvv": "card security code",
    "otp": "a one-time code",
    "emirates_id": "Emirates ID",
    "password": "password",
}
_DNS = {
    "dns_a": "website address",
    "dns_aaaa": "website address (IPv6)",
    "dns_cname": "alias (CNAME)",
    "dns_ns": "name server",
    "dns_mx": "mail server",
}
_GROUPS = (
    ("Brand", ("lookalike",)),
    ("Phishing lists", ("in_feed", "search_hit", "urlhaus_listed", "urlscan_hit")),
    ("Registration", ("created_at", "registrar")),
    ("Hosting", ("dns_a", "dns_aaaa", "dns_cname", "dns_ns", "dns_mx", "ip_asn")),
    ("Security certificates", ("certs",)),
    ("Page", ("snapshot_page", "snapshot_form", "snapshot_brand", "snapshot_blocked")),
    ("Relatives (urlscan)", ("relative_link", "relatives_run")),
)


def _dt(iso: str | None) -> datetime | None:
    return live.parse_ts(iso)


def _day(moment: datetime, now: datetime | None = None) -> str:
    """'19 Nov' in Dubai time; '8 Dec 2025' when not this year, so an old date never reads as an upcoming one."""
    local, year = moment.astimezone(live._GST), (now or datetime.now(UTC)).astimezone(live._GST).year
    return f"{local.day} {local:%b}" + ("" if local.year == year else f" {local.year}")


def _stamp(moment: datetime, now: datetime | None = None) -> str:
    """'19 Nov 07:12 GST' for sentences (Dubai time, UTC+4); the year is added when it is not this year."""
    return f"{_day(moment, now)} {moment.astimezone(live._GST):%H:%M} GST"


def age_text(seconds: float) -> str:
    """The one wording for every age on a card: whole hours under ui.yaml age_hours_max ('35 h'), whole days from there on ('2 days')."""
    hours_max = config._yaml(config.CONFIG_DIR / "ui.yaml")["age_hours_max"]
    hours = int(max(seconds, 0) // 3600)
    return "under 1 h" if hours < 1 else f"{hours} h" if hours < hours_max else f"{hours // 24} days"


def _ago(then: datetime, now: datetime) -> str:
    return age_text((now - then).total_seconds()) + " ago"


def _ui() -> dict:
    return config._yaml(config.CONFIG_DIR / "ui.yaml")


def _urgency(first_seen: str, risk: float | None, now: datetime) -> float:
    seen = _dt(first_seen)
    hours = (now - seen).total_seconds() / 3600 if seen else 10**6
    cfg = _ui()
    return (risk or 0) * next((w for h, w in cfg["freshness_steps"] if hours <= h), cfg["freshness_older"])


# ---------- queue ----------

_QUEUE_SQL = """SELECT d.fqdn, d.found_by, d.data_mode, d.state, d.risk_score, d.first_seen_at, d.brand_id, a.flags_json, a.components_json,
    (SELECT min(created_at) FROM jobs j WHERE j.target = d.fqdn) AS ingested_at,
    (SELECT j.status FROM jobs j WHERE j.kind = 'check_domain' AND j.target = d.fqdn ORDER BY j.id DESC LIMIT 1) AS job,
    (SELECT json_extract(value_json, '$.brand') FROM facts WHERE domain_id = d.id AND type = 'lookalike' AND status = 'ok' ORDER BY id DESC LIMIT 1) AS look_brand,
    (SELECT json_extract(value_json, '$.listed') FROM facts WHERE domain_id = d.id AND type = 'in_feed' AND status = 'ok' ORDER BY id DESC LIMIT 1) AS listed,
    (SELECT json_extract(value_json, '$.date') FROM facts WHERE domain_id = d.id AND type = 'created_at' AND status = 'ok' ORDER BY id DESC LIMIT 1) AS created,
    (SELECT output_json FROM ai_reviews WHERE assessment_id = a.id AND role = 'judge' AND valid = 1) AS ai_json,
    f.verdict, f.created_at AS decided_at
  FROM domains d LEFT JOIN assessments a ON a.id = (SELECT max(id) FROM assessments WHERE domain_id = d.id)
  LEFT JOIN feedback f ON f.id = (SELECT max(id) FROM feedback WHERE domain_id = d.id)"""


def brand_name(brand) -> str:
    return re.sub(r"\s*\(.*?\)", "", brand.name)


def _row(r: dict, brands: dict, now: datetime, judge_sort: bool = False) -> dict:
    comp, flags = json.loads(r["components_json"] or "{}"), json.loads(r["flags_json"] or "[]")
    risk = None if r["risk_score"] is None else round(r["risk_score"] * 100)
    brand = brands.get(r["brand_id"] or r["look_brand"])
    verdict, state = r["verdict"], r["state"]
    when = f" · {_gst_hm(r['decided_at'])}"
    if verdict in ("scam", "legit"):
        badge, glyph, label, why, tier = (
            verdict,
            "✕" if verdict == "scam" else "✓",
            GST_NAME[verdict],
            GST_NAME[verdict] + when,
            5,
        )
    elif state == "OFFICIAL":
        badge, glyph, label, why, tier = (
            "official",
            "—",
            "Official domain",
            f"{brand_name(brand) if brand else 'Brand'} · official domain",
            5,
        )
    elif state is None:
        failed = r["job"] == "failed"
        badge, glyph, label, why, tier = (
            "nodata",
            "!" if failed else "…",
            "Check failed" if failed else "Checking",
            "Check failed" if failed else "Checking…",
            2,
        )
    elif state == "NEED_MORE_DATA":
        badge, glyph, label, tier = "nodata", "—", "Risk not computed", 2
        why = f"{brand_name(brand) if brand else 'No brand'} · not enough checks {comp.get('checks', '?')}/5"
    else:
        tier = 3 if comp.get("band") in ("GRAY_LOW", "NOISE") else 1
        badge = "high" if state == "REVIEW_HIGH" else "monitor" if tier == 3 else "review"
        glyph, label = (
            str(risk),
            f"Risk {risk} of 100, {'Review now' if badge == 'high' else 'Review' if badge == 'review' else 'Monitor'}",
        )
        if state == "NOISE":
            why = comp.get("reason") or "filtered out"
        else:
            born = _dt(r["created"]) if r["created"] else None
            reason = (
                "in phishing list"
                if r["listed"]
                else f"registered {_ago(born, now)}"
                if born and (now - born).days <= 30
                else "name looks like the brand"
                if brand
                else "weak signs"
            )
            why = f"{brand_name(brand) if brand else 'No brand'} · {reason}"
            if not brand and comp.get("reason", "").startswith("Smishing pattern"):
                why = comp["reason"]
    ai = (
        triage_ai.queue_effect(r["ai_json"], flags, brand_name(brand) if brand else "the brand", judge_sort)
        if tier == 1 and verdict is None
        else None
    )
    tag = f"unclear {_gst_hm(r['decided_at'])}" if verdict == "unclear" else ""
    if verdict == "unclear":
        badge, glyph, label, tier = "unclear", "?", GST_NAME["unclear"], 4
    issued, read = _dt(r["first_seen_at"]), _dt(r["ingested_at"])
    late = bool(
        r["found_by"] == "ct_tiled"
        and issued
        and read
        and (read - issued).total_seconds() > live.cfg()["catchup_label_s"]
    )
    return {
        **{
            k: r[k]
            for k in ("fqdn", "found_by", "data_mode", "state", "first_seen_at", "ingested_at", "verdict", "decided_at")
        },
        "late_cert": late,
        "other_brand": "OTHER_BRAND" in flags,
        "brand": brand_name(brand) if brand else "",
        "reason": comp.get("reason"),
        "badge": badge,
        "glyph": glyph,
        "label": label,
        "why": why,
        "tier": tier,
        "tag": tag,
        "ai": ai,
        "ai_down": bool(ai and ai["demote"]),
        "risk": r["risk_score"] or 0,
        "urgency": _urgency(r["first_seen_at"], r["risk_score"], now),
    }


def _gst_hm(iso: str | None) -> str:
    moment = _dt(iso)
    return f"{moment.astimezone(live._GST):%H:%M} GST" if moment else ""


def queue(conn, settings, *, open_fqdn=None, from_=None, now=None) -> dict:
    """One list per view: todo = to check (review, unknown, unclear), low = low signal (GRAY_LOW / NOISE band, "Monitor"),
    decided = analyst-decided + official, filtered = NOISE, baseline = loaded as baseline (only there, unless open).
    Inside a tier: highest risk first, then the fresher one. `from_` pins the open case as row 0 of todo (§4.1)."""
    now = now or datetime.now(UTC)
    brands = {b.id: b for b in settings.brands}
    judge_sort = triage_ai.sort_enabled()
    rows = [_row(dict(r), brands, now, judge_sort) for r in conn.execute(_QUEUE_SQL)]
    rows.sort(key=lambda r: (r["decided_at"] or "") if r["tier"] in (4, 5) else r["first_seen_at"], reverse=True)
    # tiers 1-3: highest risk first; tiers 4-5 keep the latest decision first (stable sort keeps the order above). ai_down: bottom of its tier
    rows.sort(
        key=lambda r: (
            r["tier"],
            r["ai_down"],
            -r["risk"] if r["tier"] < 4 else 0,
            -r["urgency"] if r["tier"] < 4 else 0,
        )
    )
    baseline = [r for r in rows if r["found_by"] == "baseline"]
    rows = [r for r in rows if r["found_by"] != "baseline" or r["fqdn"] == open_fqdn]
    filtered = [r for r in rows if r["state"] == "NOISE" and r["tier"] == 3 and r["verdict"] is None]
    decided = [r for r in rows if r["tier"] == 5]
    filtered_ids = {r["fqdn"] for r in filtered}
    low = [r for r in rows if r["tier"] == 3 and r["fqdn"] not in filtered_ids]
    todo = [r for r in rows if r["tier"] in (1, 2, 4)]
    if from_ in ("paste", "search") and open_fqdn:
        pinned = next((r for r in rows if r["fqdn"] == open_fqdn), None)
        if pinned:
            for part in (todo, low, decided, filtered):
                part[:] = [r for r in part if r["fqdn"] != open_fqdn]
            todo.insert(0, {**pinned, "tag": "pasted" if from_ == "paste" else "from search"})
    return {
        "todo": todo,
        "low": low,
        "decided": decided,
        "filtered": filtered,
        "baseline": baseline,
        "count": sum(1 for r in todo if r["tier"] != 4),
    }


VIEWS = (
    ("todo", "To check", "to check"),
    ("low", "Low signal", "low signal"),
    ("decided", "Decided", "decided"),
    ("filtered", "Filtered out", "filtered out"),
    ("baseline", "Baseline", "baseline"),
)
VIEW_HINTS = {
    "todo": "Cases with a risk score worth a look, highest risk first. Unclear decisions are listed but not counted.",
    "low": "Weak signs only (no brand on the page, low score): kept for monitoring, highest risk first.",
    "decided": "Decided by an analyst, plus official brand domains.",
    "filtered": "Filtered out by the rules, each with its reason.",
    "baseline": "Already in phishing lists when the monitor started.",
}


def pick(q: dict, view: str, shown: int | str | None = None) -> dict:
    """The rows one view shows: its own list, its own count, the first `shown` rows (default: ui.yaml queue_page_rows).
    `shown` comes from ?rows=: anything that is not a whole number falls back to one page; the most is queue_page_rows_max."""
    page, cap = _ui()["queue_page_rows"], _ui()["queue_page_rows_max"]
    shown = int(shown) if str(shown or "").lstrip("-").isdigit() else 0
    shown = min(max(page, shown), cap)
    rows = q[view]
    total = q["count"] if view == "todo" else len(rows)
    tabs = [{"key": key, "label": label, "n": q["count"] if key == "todo" else len(q[key])} for key, label, _ in VIEWS]
    return {
        "key": view,
        "noun": next(noun for key, _, noun in VIEWS if key == view),
        "hint": VIEW_HINTS[view],
        "count": total,
        "rows": rows[:shown],
        "more": min(page, len(rows) - shown) if len(rows) > shown else 0,
        "next_rows": shown + page,
        "shown": shown,
        "page": page,
        "listed": len(rows),
        "tabs": tabs,
    }


# ---------- case ----------


def _src(fact: dict) -> str:
    return _SRC.get(fact["source"], fact["source"])


_SNAPSHOT_CFG: dict = {}


def _snapshot_cfg() -> dict:
    """scoring.yaml snapshot section, read once (the job-offer reason uses the same word lists as scoring)."""
    if not _SNAPSHOT_CFG:
        _SNAPSHOT_CFG.update(config._yaml(config.CONFIG_DIR / "scoring.yaml")["snapshot"])
    return _SNAPSHOT_CFG


def _points_total(comp: dict) -> str | None:
    """'= 11.5 points; 12 points or more = risk 100, so 11.5 points = risk 96': the risk number is P / p_scale (scoring.assess), shown so the listed points add up."""
    if not comp or comp.get("P") is None or not comp.get("breakdown"):
        return None
    scale = config._yaml(config.CONFIG_DIR / "scoring.yaml")["bands"]["p_scale"]
    risk = round(min(max(comp["P"] / scale, 0), 1) * 100)
    return f"= {comp['P']:g} points; {scale:g} points or more = risk 100, so {comp['P']:g} points = risk {risk}"


def _fact_line(fact: dict, brands: dict, now: datetime) -> dict:
    """One evidence row in plain words: text, short (queue wording), rank (lower = stronger reason; None = not a reason), source label."""
    kind, value, status = fact["type"], fact["value"], fact["status"]
    line = {
        "id": fact["id"],
        "type": kind,
        "src": _src(fact),
        "at": fact["fetched_at"],
        "mode": fact["data_mode"],
        "nc": False,
        "rank": None,
    }
    if kind.startswith("snapshot_") and status == "error":
        return {**line, "text": fact["error"], "nc": True}
    if status == "error":
        return {**line, "text": source_text.not_checked_text(line["src"].lower(), fact["error"]), "nc": True}
    if status == "missing":
        text = (
            "Registration date: unknown (the registry had no record)"
            if kind == "created_at"
            else f"No {_DNS[kind]} found"
            if kind in _DNS
            else "No record"
        )
        return {**line, "text": text}
    if kind == "in_feed":
        names = ", ".join(_FEED_NAMES.get(n, n) for n in value.get("feeds", []))
        if not value.get("listed"):
            return {**line, "text": "Not in the phishing lists we read"}
        since = _dt(value.get("first_listed_at"))
        return {
            **line,
            "src": f"Phishing list {names}",
            "text": f"Listed in {names}" + (f" since {_stamp(since)}" if since else ""),
            "rank": 3,
        }
    if kind == "lookalike":
        if value.get("method") == "generic_name":
            return {
                **line,
                "text": f"Name has the lure word “{value['lure']}” on a cheap .{value['tld']} domain; no brand identified",
                "rank": 2,
            }
        if value.get("method") == "smishing_pattern":
            return {
                **line,
                "text": f"Smishing pattern, target unclear: UAE word “{', '.join(value['context_words'])}” on a cheap .{value['tld']} domain with a random-looking name “{value['label']}”",
                "rank": 2,
            }
        brand = brands.get(value.get("brand"))
        shown = f"“{value['keyword']}”" if value.get("keyword") else "a brand name"
        how = {
            "edit-distance": f"Name is one edit away from {shown}",
            "homoglyph": f"Name imitates {shown} with look-alike characters",
            "idn": f"Name imitates {shown} with look-alike characters",
        }.get(value.get("method"), f"Name contains {shown}")
        return {
            **line,
            "text": f"{how} — looks like {brand_name(brand)} ({brand.official_domains[0]})" if brand else how,
            "rank": 2,
        }
    if kind == "created_at":
        born = _dt(value.get("date"))
        local = born.astimezone(live._GST) if born else None
        days = (now - born).days if born else None  # same clock and wording as the timeline (age_text)
        text = f"Registered {_ago(born, now)} ({local.day} {local:%b %Y})" if local else "Registration date: unknown"
        return {**line, "text": text, "rank": 4 if days is not None and days <= 30 else None}
    if kind == "registrar":
        return {**line, "text": f"Registrar: {value.get('name', 'unknown')}"}
    if kind == "certs":
        first = _dt(value.get("first_issued"))
        text = (
            f"{value.get('count', '?')} certificate(s), first issued {_ago(first, now)}"
            + (f" by {value['issuer']}" if value.get("issuer") else "")
            if first
            else "No certificate found"
        )
        return {**line, "text": text}
    if kind == "ip_asn":
        return {
            **line,
            "text": f"Hosting network AS{value.get('asn')}"
            + (f" {value['name']}" if value.get("name") else "")
            + f" for {value.get('ip')}",
        }
    if kind in _DNS:
        records = ", ".join(map(str, value.get("records", []))) or "none"
        return {
            **line,
            "text": f"{_DNS[kind].capitalize()}: {records}",
        }
    if kind == "snapshot_page":
        offer = _offers_work_via_messenger(value, _snapshot_cfg())
        line = (
            {**line, "rank": 0, "reason": "Page offers jobs or visas and asks to contact via WhatsApp or Telegram"}
            if offer
            else line
        )  # the job-scam sign is the strongest reason
        return {
            **line,
            "text": f"Page title “{value.get('title') or ''}”"
            + (f", redirected via {len(value['redirects']) - 1} hop(s)" if len(value.get("redirects", [])) > 1 else "")
            + (f"; tried {', '.join(value['disabled'])} — refused by the sandbox" if value.get("disabled") else "")
            + (f"; parked domain (ad page, “{value['parked']}”)" if value.get("parked") else "")
            + (
                f"; page contacts {', '.join(value['exfil'])} — a channel kits use to send stolen data"
                if value.get("exfil")
                else ""
            )
            + (
                f"; page loads files from {', '.join(value['hotlinks'])} (official site) — a copied page"
                if value.get("hotlinks")
                else ""
            ),
        }
    if kind == "snapshot_form":
        asks = [_ASKS[a] for a in value["asks"] if a in _ASKS]
        return {
            **line,
            "rank": 0 if asks else None,
            "reason": f"Login page asks for {', '.join(asks[:-1])}{' and ' if len(asks) > 1 else ''}{asks[-1]}"
            if asks
            else None,
            "text": "Form fields on the page (names only, never values): "
            + ", ".join(f["name"] or f["type"] for f in value["fields"])
            + (f" — asks for {', '.join(a.replace('_', ' ') for a in value['asks'])}" if value["asks"] else ""),
        }
    if kind == "snapshot_brand":
        if not value:
            return {**line, "text": "No brand seen on the page"}
        brand = brands.get(value["brand"])
        return {
            **line,
            "text": f"Page shows the {'logo' if set(value['via']) & {'logo', 'favicon', 'page'} else 'name'} of {brand_name(brand) if brand else value['brand']} on a site that is not its own",
            "rank": 1,
        }
    if kind == "snapshot_blocked":
        return {**line, "text": value["message"]}
    if kind == "search_hit":
        return {**line, "text": f"Found by web search “{value.get('query')}” (rank {value.get('rank')})", "rank": 5}
    if kind == "urlhaus_listed":
        tags = f" ({', '.join(value['tags'])})" if value.get("tags") else ""
        return {
            **line,
            "text": f"Listed in URLhaus: {value.get('threat') or 'unknown threat'}{tags}, {value.get('url')}",
            "rank": 3,
        }
    if kind == "urlscan_hit":
        seen = (
            f"page titled “{value.get('title')}”"
            if value.get("match") == "title"
            else "uses the official brand favicon"
        )
        return {
            **line,
            "text": f"urlscan: {seen} on a domain that is not official (scanned {(value.get('scan_date') or '')[:10]}, {value.get('result_url')})",
            "rank": 5,
        }
    if kind == "relative_link":
        return {
            **line,
            "text": f"{value.get('reason')} (urlscan scan {(value.get('scan_date') or '')[:10]}, {value.get('result_url')})",
        }
    if kind == "relatives_run":
        return {**line, "text": f"Find relatives: {value.get('message')}"}
    return {**line, "text": f"{kind}: {json.dumps(value)}"}


def _checks(facts: list[dict], assessment) -> tuple[int | None, list[str]]:
    done = {
        name for name, types in _CHECKS.items() if any(f["type"] in types and f["status"] != "error" for f in facts)
    }
    return (assessment["components"].get("checks") if assessment else None), [
        _CHECK_NAMES[n] for n in _CHECKS if n not in done and facts
    ]


def _links_clause(edges: list[dict], fqdn: str) -> str | None:
    if not edges:
        return None
    others = {n for e in edges for n in (e["a"], e["b"])} - {fqdn}
    strongest = next((e for e in edges if e["level"] == "strong"), edges[0])
    return f"{strongest['title'].split(' (')[0].split(', urlscan scan')[0]} as {len(others)} other site{'s' if len(others) != 1 else ''}"


def link_reasons(edges: list[dict]) -> list[dict]:
    """One line per distinct reason: edges with the same sentence and level share their evidence (E-numbers)."""
    groups: dict[tuple, dict] = {}
    for e in edges:
        group = groups.setdefault(
            (e["sentence"], e["level"]), {"sentence": e["sentence"], "level": e["level"], "evidence": []}
        )
        group["evidence"] += [ev for ev in e["evidence"] if all(ev["id"] != x["id"] for x in group["evidence"])]
    return list(groups.values())


def case_context(
    domain: dict,
    facts: list[dict],
    assessment,
    feedback,
    check: dict,
    edges: list[dict],
    brands: dict,
    now: datetime | None = None,
) -> dict:
    """Everything ①-③ need. `domain.state` None = still checking or check failed."""
    now = now or datetime.now(UTC)
    lines = [_fact_line(f, brands, now) for f in facts]
    comp = assessment["components"] if assessment else {}
    if (
        assessment and "PAGE_BRAND_NOT_COUNTED" in assessment["flags"]
    ):  # scoring left the name-only page hit out (own address, parked page): so does the card
        shown = next((f["value"] for f in facts if f["type"] == "snapshot_brand" and f["value"]), {})
        name = brand_name(brands[shown["brand"]]) if shown.get("brand") in brands else shown.get("brand", "the brand")
        lines = [
            {**ln, "rank": None, "text": f"Page names {name} only in its own address or a parking text — not counted"}
            if ln["type"] == "snapshot_brand" and ln["rank"] is not None
            else ln
            for ln in lines
        ]
    look = next((f["value"] for f in facts if f["type"] == "lookalike" and f["status"] == "ok"), None)
    brand = brands.get(domain["brand_id"] or (look or {}).get("brand"))
    state, verdict = domain["state"], feedback["verdict"] if feedback else None
    failed = state is None and bool(check and check.get("text", "") and check["text"].startswith("Check failed"))
    reasons = sorted((ln for ln in lines if ln["rank"] is not None and not ln["nc"]), key=lambda ln: ln["rank"])
    if edges:
        reasons.append(
            {
                "text": edges[0]["sentence"],
                "src": "Link analysis",
                "at": edges[0]["evidence"][0]["fetched_at"] if edges[0]["evidence"] else None,
                "ids": [e["id"] for e in edges[0]["evidence"]],
                "rank": 6,
            }
        )
        reasons.sort(key=lambda ln: ln["rank"])
    generic = bool(assessment and "GENERIC_PHISHING" in assessment["flags"])
    reasons = [{**r, "ids": r.get("ids") or [r["id"]]} for r in reasons[: 3 - generic]]
    if generic:  # no brand to name: the reason is the new domain with a page that steals data
        reasons.insert(
            0,
            {
                "text": comp["reason"],
                "src": "Scoring",
                "at": None,
                "ids": [ln["id"] for ln in lines if ln["type"].startswith("snapshot_") and ln["rank"] == 0][:1],
                "rank": -1,
            },
        )

    clauses = []
    feed = next((ln for ln in lines if ln["type"] == "in_feed" and ln["rank"] == 3), None)
    age = next((ln for ln in lines if ln["type"] == "created_at" and ln["rank"] == 4), None)
    if feed:
        clauses.append(feed["text"].replace("Listed in", "listed in", 1))
    if _links_clause(edges, domain["fqdn"]):
        clauses.append(_links_clause(edges, domain["fqdn"]))
    if age:
        clauses.append(age["text"].split(" (")[0].replace("Registered", "registered", 1))
    head = (
        f"Looks like {brand_name(brand)} ({brand.official_domains[0]})"
        if brand and state != "OFFICIAL"
        else "Phishing, brand not identified"
        if generic
        else "Smishing pattern, target unclear"
        if (look or {}).get("method") == "smishing_pattern"
        else "No brand match found"
    )
    body = (
        head
        + (", " + ", ".join(clauses[:-1]) + (" and " if len(clauses) > 1 else "") + clauses[-1] if clauses else "")
        + "."
    )
    if state == "OFFICIAL":
        body = f"Official domain of {brand_name(brand) if brand else 'a listed brand'} (from our verified list)."
    elif state == "NEED_MORE_DATA":
        body += " Not enough checks completed to judge."
    elif state == "NOISE":
        body = f"Filtered out: {comp.get('reason', 'no sign of fraud')}."
    elif state is None:
        body = (
            "Check failed — the sources did not answer."
            if failed
            else "Checking this link now — facts appear below as they arrive."
        )
    prefix = ""
    if verdict in ("scam", "legit"):
        moment = _dt(feedback["created_at"])
        prefix = f"{'Confirmed scam' if verdict == 'scam' else 'Marked legit'} by analyst, {moment.astimezone(live._GST).day} {moment.astimezone(live._GST):%b}."

    done, missing = _checks(facts, assessment)
    risk = None if state is None or state in ("OFFICIAL", "NEED_MORE_DATA") else round(domain["risk_score"] * 100)
    tone = {"REVIEW_HIGH": "high", "REVIEW": "review"}.get(state, "nodata")
    if verdict in ("scam", "legit") or (tone == "review" and comp.get("band") in ("GRAY_LOW", "NOISE")):
        tone = "decided"
    chip = (
        {"cls": "scam", "glyph": "✕", "text": GST_NAME["scam"]}
        if verdict == "scam"
        else {"cls": "", "glyph": "✓", "text": "Marked legit by analyst"}
        if verdict == "legit"
        else {"cls": "official", "glyph": "✓", "text": "Official domain"}
        if state == "OFFICIAL"
        else {"cls": "nodata", "glyph": "!", "text": "Check failed"}
        if failed
        else {"cls": "nodata", "glyph": "…", "text": "Checking…"}
        if state is None
        else {"cls": "nodata", "glyph": "?", "text": "Need more data"}
        if state == "NEED_MORE_DATA"
        else None
    )
    groups = [{"name": name, "rows": [ln for ln in lines if ln["type"] in types]} for name, types in _GROUPS]
    known = {t for _, types in _GROUPS for t in types}
    groups = [*groups, {"name": "Other", "rows": [ln for ln in lines if ln["type"] not in known]}]
    groups = [g for g in groups if g["rows"]]
    flags = assessment["flags"] if assessment else []
    headline = (
        ("Checking…" if not failed else "Check failed")
        if state is None
        else "Not enough data yet"
        if state == "NEED_MORE_DATA"
        else "Filtered out"
        if state == "NOISE"
        else f"Official domain of {brand_name(brand)}"
        if state == "OFFICIAL" and brand
        else "Official domain"
        if state == "OFFICIAL"
        else f"Looks like {brand_name(brand)}"
        if brand
        else "Phishing, brand not identified"
        if generic
        else "Smishing pattern, target unclear"
        if (look or {}).get("method") == "smishing_pattern"
        else "No brand match found"
    )
    return {
        "headline": headline,
        "sentence": body,
        "prefix": prefix,
        "risk": risk,
        "tone": tone,
        "chip": chip,
        "checks": done,
        "not_checked": missing,
        "reasons": reasons,
        "groups": groups,
        "evidence_count": len(lines),
        "failed": failed,
        "other_brand": "OTHER_BRAND" in flags,
        "breakdown": comp.get("breakdown"),
        "points_total": _points_total(comp),
        "band": comp.get("band"),
        "links_clause": _links_clause(edges, domain["fqdn"]),
        "node_count": len({n for e in edges for n in (e["a"], e["b"])}) - 1 if edges else 0,
        "brand": brand_name(brand) if brand else None,
    }


def timeline(domain: dict, facts: list[dict], ingested_at: str | None, now: datetime | None = None) -> list[dict]:
    """Freshness line from real data only: registered -> certificate -> found by us -> listed by a phishing list. A missing piece is omitted.
    Each part: {label, text, lead}; `lead` marks the moment we found it."""
    now = now or datetime.now(UTC)
    ok = {f["type"]: f["value"] for f in facts if f["status"] == "ok"}
    parts = []
    born = _dt((ok.get("created_at") or {}).get("date"))
    if born:
        hours = (now - born).total_seconds() / 3600
        parts.append(
            (
                born,
                "Registered",
                _ago(born, now)
                if 0 <= hours < config._yaml(config.CONFIG_DIR / "ui.yaml")["age_hours_max"]
                else _day(born, now),
            )
        )
    cert = (
        _dt(domain["first_seen_at"])
        if domain["found_by"] == "ct_tiled"
        else _dt((ok.get("certs") or {}).get("first_issued"))
    )
    if cert and born and cert < born:
        cert = None  # a certificate older than the registration belongs to a previous registrant: it would tell an out-of-order story
    if cert:
        parts.append((cert, "Certificate", _stamp(cert, now)))
    found = _dt(ingested_at)
    if found:
        cfg = config._yaml(config.CONFIG_DIR / "ui.yaml")
        secs = (found - cert).total_seconds() if cert else -1
        since_reg = (found - born).total_seconds() if born else -1
        if 0 <= secs < 2 * 3600:
            gap = f" (+{round(secs / 60)} min after the certificate)"
        elif 0 <= secs < cfg["timeline_gap_cert_hours"] * 3600:
            gap = f" (+{round(secs / 3600)} h after the certificate)"
        elif 0 <= since_reg < cfg["timeline_gap_registration_days"] * 86400:
            gap = f" ({age_text(since_reg)} after registration)"
        else:
            gap = ""
        parts.append((found, "Found by ScamShield", _stamp(found, now) + gap))
    listed = _dt((ok.get("in_feed") or {}).get("first_listed_at")) if (ok.get("in_feed") or {}).get("listed") else None
    if listed:
        names = ", ".join(_FEED_NAMES.get(n, n) for n in ok["in_feed"].get("feeds", []))
        parts.append((listed, f"Listed by {names}" if names else "Listed by a phishing list", _stamp(listed, now)))
    return [
        {"label": label, "text": text, "lead": label == "Found by ScamShield"}
        for _, label, text in sorted(parts, key=lambda p: p[0])
    ]


def neighbour_tones(conn, edges: list[dict]) -> dict[str, str]:
    """Node colour per linked domain: same classes as the queue badge, from the stored state (unknown -> not enough checks)."""
    names = {n for e in edges for n in (e["a"], e["b"])}
    out = {}
    for row in (
        conn.execute(
            f"SELECT fqdn, state, (SELECT verdict FROM feedback WHERE domain_id = domains.id ORDER BY id DESC LIMIT 1) AS v FROM domains WHERE fqdn IN ({','.join('?' * len(names))})",
            sorted(names),
        )
        if names
        else []
    ):
        out[row["fqdn"]] = (
            "scam" if row["v"] == "scam" else {"REVIEW_HIGH": "high", "REVIEW": "review"}.get(row["state"], "nodata")
        )
    return out


def monitor_time(conn) -> str | None:
    row = conn.execute("SELECT max(at) FROM heartbeats WHERE ok = 1 AND loop NOT IN ('boot', 'pause')").fetchone()[0]
    return row


def last_saved(conn) -> dict | None:
    row = conn.execute(
        "SELECT d.fqdn, f.verdict, f.created_at FROM feedback f JOIN domains d ON d.id = f.domain_id ORDER BY f.id DESC LIMIT 1"
    ).fetchone()
    return dict(row) if row else None


def search_last_run(conn) -> str | None:
    return conn.execute("SELECT max(run_at) FROM search_runs").fetchone()[0]


def next_after(todo: list[dict], current: str | None) -> str | None:
    """The case ④ promises to open after saving: the item below the current one, else the top one that is not the current one."""
    names = [r["fqdn"] for r in todo if r["tier"] != 4]
    if current in names and names.index(current) + 1 < len(names):
        return names[names.index(current) + 1]
    return next((n for n in names if n != current), None)


def load_case(conn, settings, fqdn: str, now: datetime | None = None) -> dict | None:
    """Everything the case area shows for one domain, or None when unknown. One place for routes and partials."""
    now = now or datetime.now(UTC)  # one clock for every age on the card (reasons, evidence and timeline)
    domain = conn.execute("SELECT * FROM domains WHERE fqdn = ?", (fqdn,)).fetchone()
    if domain is None:
        return None
    domain = dict(domain)
    facts = [{**dict(f), "value": json.loads(f["value_json"])} for f in db.current_facts(conn, domain["id"])]
    row = conn.execute(
        "SELECT flags_json, components_json, created_at FROM assessments WHERE domain_id = ? ORDER BY id DESC LIMIT 1",
        (domain["id"],),
    ).fetchone()
    assessment = (
        {
            "flags": json.loads(row["flags_json"]),
            "components": json.loads(row["components_json"]),
            "at": row["created_at"],
        }
        if row
        else None
    )
    fb = conn.execute(
        "SELECT verdict, reason, analyst, created_at FROM feedback WHERE domain_id = ? ORDER BY id DESC LIMIT 1",
        (domain["id"],),
    ).fetchone()
    edges = graph.card_view(conn, fqdn, settings.scoring, settings.shared_infra)
    from scamshield.web import routes  # check_state lives with the routes that poll it

    ctx = case_context(
        domain,
        facts,
        assessment,
        dict(fb) if fb else None,
        routes._check_state(conn, fqdn),
        edges,
        {b.id: b for b in settings.brands},
        now,
    )
    ingested = conn.execute("SELECT min(created_at) FROM jobs WHERE target = ?", (fqdn,)).fetchone()[0]
    shot = conn.execute(
        "SELECT id, captured_at FROM artifacts WHERE domain_id = ? AND kind = 'screenshot' ORDER BY id DESC LIMIT 1",
        (domain["id"],),
    ).fetchone()
    last = max(
        (f for f in facts if f["type"] in ("snapshot_blocked", "snapshot_page")), key=lambda f: f["id"], default=None
    )  # the log is append-only: only the newest attempt tells what the analyst sees now
    stopped = (
        (last["value"]["message"] if last["type"] == "snapshot_blocked" else last["error"])
        if last and (last["type"] == "snapshot_blocked" or last["status"] == "error")
        else None
    )
    run = max((f for f in facts if f["type"] == "relatives_run"), key=lambda f: f["id"], default=None)
    return {
        "relatives": {"message": run["value"].get("message"), "at": run["fetched_at"]} if run else None,
        "snap": {
            "id": shot["id"] if shot and not stopped else None,
            "at": shot["captured_at"] if shot else None,
            "message": stopped,
        },
        "domain": domain,
        "fqdn": fqdn,
        "assessment": assessment,
        "feedback": dict(fb) if fb else None,
        "check": routes._check_state(conn, fqdn),
        "timeline": timeline(domain, facts, ingested, now),
        "edges": edges,
        "link_reasons": link_reasons(edges),
        "tones": neighbour_tones(conn, edges),
        "c": ctx,
        "explanation": explain.card_state(conn, fqdn) if domain["state"] is not None else None,
        "ai_review": triage_ai.card_state(conn, fqdn),
    }
