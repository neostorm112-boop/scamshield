"""Takedown draft: a plain-text abuse report built from a template and the evidence we already store. Never sent by the app; a human reads, edits and sends it."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from scamshield.enrich.lookalike import is_official
from scamshield.netsafe import icann_registrable_of
from scamshield.web.view import brand_name

_EVIDENCE = (
    "lookalike",
    "created_at",
    "registrar",
    "ip_asn",
    "certs",
    "snapshot_page",
    "snapshot_form",
    "snapshot_brand",
    "in_feed",
    "urlhaus_listed",
    "urlscan_hit",
)


def _c(value, cap: int = 200) -> str:
    """Stored text can come from the attacker's page: one line, bounded, so it cannot add paragraphs or fake our own statements."""
    return re.sub(r"\s+", " ", str(value)).strip()[:cap]


def _refusal(case: dict, brands: dict, verdict: str | None) -> str | None:
    fqdn = case["fqdn"]
    if case["domain"]["state"] == "OFFICIAL" or is_official(fqdn, list(brands.values())):
        return "this is an official domain of a brand we protect"
    return "the analyst marked this domain as legitimate" if verdict == "legit" else None


def build(case: dict, facts: list[dict], shots: list[str], brands: dict, now: datetime | None = None) -> str:
    """`case` is view.load_case(); `facts` its current facts (with parsed values); `shots` capture times (UTC) of stored screenshots."""
    fqdn, fb = case["fqdn"], case["feedback"]
    verdict = fb["verdict"] if fb else None
    if reason := _refusal(case, brands, verdict):
        return f"Do not send: {reason}. No takedown draft is prepared for {_c(fqdn)}.\n"
    ok = lambda kind: [f for f in facts if f["type"] == kind and f["status"] == "ok"]
    look = next(iter(ok("lookalike")), None)
    brand = brands.get(case["domain"]["brand_id"] or (look["value"].get("brand") if look else None))
    target = f"{_c(brand_name(brand))} (official: {_c(', '.join(brand.official_domains))})" if brand else None
    registrar = next(iter(ok("registrar")), None)
    out = [
        "DRAFT — review before sending. Prepared by ScamShield for the analyst on duty; evidence collected automatically.",
        f"Generated {(now or datetime.now(UTC)):%Y-%m-%d %H:%M} UTC. Nothing here was sent by ScamShield.",
        "",
    ]
    out += [
        f"Subject: Abuse report: {_c(fqdn)} "
        + (f"impersonating {_c(brand_name(brand))}" if brand else "suspected phishing"),
        "",
        "Hello,",
        "",
        f"We are reporting the domain {_c(fqdn)} (URL: https://{_c(fqdn)}/)"
        + (
            f", which {'was confirmed by our analyst to impersonate' if verdict == 'scam' else 'appears to impersonate'} {target}."
            if target
            else "."
        ),
        "Confirmed by analyst: this is a scam site."
        if verdict == "scam"
        else "This is an automated assessment and has not been confirmed by an analyst.",
        "",
        "Evidence (source, time UTC):",
    ]
    out += [
        f"- {_c(ln['text'])} [{_c(ln['src'])}, {_c(ln['at'])}]"
        for g in case["c"]["groups"]
        for ln in g["rows"]
        if ln["type"] in _EVIDENCE and not ln["nc"]
    ]
    if shots:
        out += ["", *[f"Screenshot: available in the ScamShield case {_c(fqdn)}, captured {_c(at)}" for at in shots]]
    out += ["", "Recipients:"]
    if registrar:
        name, email = _c(registrar["value"]["name"]), _c(registrar["value"].get("abuse_email") or "")
        out.append(
            f"- Registrar: {name}, abuse email: {email}"
            if email
            else f"- Registrar: {name}; abuse email not stored, find the abuse contact at {name} / whois"
        )
    else:
        out.append(
            f"- Registrar: unknown (no registry data); look it up at https://rdap.org/domain/{_c(icann_registrable_of(fqdn) or fqdn)}"
        )
    for f in ok("ip_asn"):
        v = f["value"]
        out.append(
            f"- Hosting provider: AS{_c(v.get('asn'))}{' ' + _c(v['name']) if v.get('name') else ''} (IP {_c(v.get('ip'))}); abuse contact: look up via https://rdap.org/ip/{_c(v.get('ip'))}"
        )
    if not ok("ip_asn"):
        out.append("- Hosting provider: unknown (no hosting data)")
    edges = [e for e in case["edges"] if e["title"].startswith("same registrar")]
    same = [
        n
        for n in sorted({n for e in edges for n in (e["a"], e["b"])} - {fqdn})
        if case["tones"].get(n) in ("scam", "high", "review")
    ]
    if same:
        out += [
            "",
            f"Related domains at the same registrar (linked by: {_c(edges[0]['sentence'])}):",
            *[f"- {_c(n)}" for n in same],
        ]
    out += ["", "Please review and take appropriate action. Thank you.", ""]
    return "\n".join(out)
