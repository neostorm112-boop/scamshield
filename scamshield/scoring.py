"""Pure assessment by evidence points (see docs/ARCHITECTURE.md).
B = brand-fit, R = risk, P = B + R. Unknown evidence is 0 points and never benign: NOISE needs positive evidence."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

from scamshield.contracts import Assessment
from scamshield.enrich.lookalike import _ICANN, is_official, is_regional_official

_CHECKS = {
    "dns": ("dns_a", "dns_aaaa", "dns_cname", "dns_ns", "dns_mx"),
    "asn": ("ip_asn",),
    "age": ("created_at",),
    "certs": ("certs",),
    "feed": ("in_feed",),
}
_FEED_NAMES = {"openphish": "OpenPhish", "phishing_database": "Phishing.Database", "phishing_army": "phishing.army"}
_POSITION = {
    "registrable": ("registrable_token", "brand in name"),
    "subdomain": ("subdomain_label", "brand as subdomain"),
    "platform_label": ("platform_label", "brand on hosting platform"),
}
_RISK_EVIDENCE = {
    "feed",
    "cert",
    "edge",
    "host",
    "form",
    "exfil",
    "offer",
}  # R_ev: points that are evidence of a fraud site (not age, not "resolves")
_STATE = {
    "NOISE": "NOISE",
    "NEED_MORE_DATA": "NEED_MORE_DATA",
    "FURTHER": "REVIEW_HIGH",
    "GRAY": "REVIEW",
    "GRAY_LOW": "REVIEW",
}


_UAE_WORD = re.compile(
    r"(?<!\w)(uae|u\.a\.e|dubai|abu dhabi|sharjah|ajman|emirates|aed|الإمارات|دبي|أبوظبي|الشارقة|درهم)(?!\w)"
)


def _registrable(host: str) -> str:
    parts = _ICANN((host or "").lower().rstrip("."))
    return f"{parts.domain}.{parts.suffix}" if parts.domain and parts.suffix else (host or "").lower()


def page_brand_names(title: str, text: str, own_hosts, brand, cfg: dict) -> set[str]:
    """Brand names (full name, official domain, keyword >= name_min_len) the page text shows. The page's own address is cut out first:
    a blank WordPress titled with its host (salik.enterprises) prints the brand only because the domain carries it.
    Ordinary words (ambiguous_names) count only with a UAE word within ambiguous_window characters."""
    haystack = f"{title}\n{text}".lower()
    for host in {h.lower().rstrip(".") for h in own_hosts if h}:
        haystack = re.sub(rf"(?<![\w.-])(?:[\w-]+\.)*{re.escape(host)}(?![\w-])", " ", haystack)
    full = re.sub(r"\s*\(.*?\)", "", brand.name).lower()
    names = {
        *([full] if " " in full else []),
        *brand.official_domains,
        *(k for k in brand.keywords if len(k) >= cfg["name_min_len"]),
    }  # a one-word name ("Emirates", "noon") is an ordinary word on any page
    hits = {n for n in names if re.search(rf"(?<!\w){re.escape(n)}(?!\w)", haystack)}
    near = cfg["ambiguous_window"]

    def next_to_uae(word: str) -> bool:
        return any(
            _UAE_WORD.search(haystack, max(m.start() - near, 0), m.end() + near)
            for m in re.finditer(rf"(?<!\w){re.escape(word)}(?!\w)", haystack)
        )

    if (
        hits and hits <= set(cfg.get("ambiguous_names", [])) and not any(next_to_uae(h) for h in hits)
    ):  # "sewa" is Indonesian for "rent", "darb" Arabic for "road"
        return set()
    return hits


def _fmt(points: float, label: str) -> str:
    return f"{points:+g} {label}" if points else f"0 {label}"


def _when(text: str) -> datetime:
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _brand_fit(
    fqdn: str, value: dict, cfg: dict, foreign: set[str], short_max: int, prior: dict
) -> tuple[list[tuple[str, float]], dict[str, str], list[str]]:
    """Rows (label, points), NEG signals {B9|B10|B12: reason}, flags for one lookalike fact value."""
    rows, neg, flags = [], {}, []
    if (
        value.get("method") == "generic_name"
    ):  # the lure word only routes the name to a check; it says nothing about a brand
        return [], neg, flags
    if value.get("method") == "smishing_pattern":  # no brand: one flat prior, never enough for FURTHER
        return [("UAE smishing pattern", cfg["smishing_pattern"])], neg, flags
    keyword, position, method = value.get("keyword", ""), value.get("position"), value.get("method")
    if position in _POSITION:
        key, label = _POSITION[position]
        base = cfg[key] * (cfg["edit_factor"] if method == "edit-distance" else 1)
        rows.append((label + (" (edit distance)" if method == "edit-distance" else ""), base))
    if method in ("homoglyph", "idn"):
        rows.append((f"{method} spelling", cfg["homoglyph_bonus"]))
    if (
        value.get("dev_label") and position == "subdomain"
    ):  # beta-etisalat.ipixsolutions.net: a vendor's test copy, lowered, not dropped
        rows.append((f"dev/staging word `{value['dev_label']}` in the subdomain", cfg.get("dev_subdomain", 0)))
    words = value.get("context_words") or []
    if words:
        rows.append((f"context: {', '.join(words)}", min(len(words) * cfg["context_each"], cfg["context_max"])))
    if 0 < len(keyword) <= short_max:
        rows.append(
            (f"short keyword `{keyword}`", prior.get(keyword, cfg["short_keyword_prior"]))
        )  # brands.yaml prior_points wins
    if value.get("restricted_zone") and position == "registrable" and value.get("label") == keyword:
        rows.append(("brand token is the registrable label in a restricted zone", cfg["restricted_own_label"]))
        neg["B9"] = (
            f"brand token `{keyword}` is the registrable label in a restricted zone (academic/government/non-profit)"
        )
    other = sorted(set(re.split(r"[^a-z0-9]+", fqdn)) & foreign)
    if other:
        rows.append((f"other brand `{other[0]}` in name", cfg["foreign_brand"]))
        neg["B10"] = f"other brand `{other[0]}` in name"
        flags.append("OTHER_BRAND")
    if fqdn.endswith(".gov.ae"):
        total = sum(points for _, points in rows)
        rows.append(("*.gov.ae host (restricted registration)", total * cfg["gov_ae_factor"] - total))
        neg["B12"] = "*.gov.ae host (restricted registration) with weak brand-fit"
        flags.append("GOV_AE")
    return rows, neg, flags


def _risk(
    fqdn: str, facts, look: dict | None, edges, neighbours, feed_neighbours, cfg: dict, edge_min: float, feed_min: float
) -> tuple[list[tuple[str, str, float]], list[str]]:
    """Rows (kind, label, points) and flags; a check without an ok fact gives a 0-point "unknown" row, never a guess."""
    ok = {}
    for fact in facts:
        if fact.status == "ok":
            ok[fact.type] = fact
    rows, flags = [], []
    feed = ok.get("in_feed")
    if feed and feed.value.get("listed"):
        name = max(feed.value.get("feeds", []), key=lambda n: cfg["feed"].get(n, 0), default=None)
        if name:
            rows.append(("feed", _FEED_NAMES.get(name, name), cfg["feed"].get(name, 0)))
    created = ok.get("created_at")
    if created and created.value.get("date"):
        if (
            look and look.get("position") == "registrable"
        ):  # a platform's or hacked site's age says nothing about the subdomain
            days = (_when(created.fetched_at) - _when(created.value["date"])).days
            points = (
                cfg["age_le_30"]
                if days <= cfg["age_recent_days"]
                else cfg["age_le_180"]
                if days <= cfg["age_young_days"]
                else cfg["age_gt_730"]
                if days > cfg["age_old_days"]
                else 0
            )
            rows.append(
                ("age", f"domain age {days} d when checked", points)
            )  # counted at the registry answer, not at page view
        elif look:
            rows.append(("age", "age of the hosting domain not counted", 0))
    else:
        rows.append(("age", "age unknown", 0))
    certs = ok.get("certs")
    if certs and certs.value.get("first_issued"):
        if (_when(certs.fetched_at) - _when(certs.value["first_issued"])).days <= cfg["cert_recent_days"]:
            rows.append(("cert", f"certificate issued within {cfg['cert_recent_days']} days", cfg["cert_le_7d"]))
    else:
        rows.append(("cert", "certificate unknown", 0))

    def other(edge):
        return edge.b if edge.a == fqdn else edge.a

    if any(e.strength >= edge_min and other(e) in neighbours for e in edges):
        rows.append(("edge", "linked to a confirmed scam domain", cfg["edge_confirmed"]))
    elif any(e.strength >= feed_min and other(e) in feed_neighbours for e in edges):
        rows.append(("edge", "linked to a domain in a phishing list", cfg["edge_in_feed"]))
    if any(f.type in ("dns_a", "dns_aaaa") and f.status == "ok" for f in facts):
        rows.append(("resolves", "resolves", cfg["resolves"]))
    if look and look.get("restricted_zone") and look.get("position") != "registrable":
        rows.append(("host", "brand on a government/university/non-profit site", cfg["restricted_host"]))
        flags.append("COMPROMISED_HOST")
    return rows, flags


def _young(facts, max_days: int) -> bool | None:
    """Registered within max_days (else first certificate within max_days); None when neither date is known."""
    ok = {f.type: f for f in facts if f.status == "ok"}
    for kind, key in (("created_at", "date"), ("certs", "first_issued")):
        if ok.get(kind) and ok[kind].value.get(key):
            return (_when(ok[kind].fetched_at) - _when(ok[kind].value[key])).days <= max_days
    return None


def _offers_work_via_messenger(page: dict, cfg: dict) -> bool:
    """A job / visa offer and a messenger contact on the same page: the advance-fee job scam (careemglobal.com)."""
    text = f"{page.get('title', '')}\n{page.get('text', '')}".lower()
    for phrase in cfg["offer_noise_phrases"]:
        text = text.replace(phrase, " ")
    words = "|".join(re.escape(w.lower()) for w in cfg["offer_words"])
    return bool(re.search(rf"(?<!\w)(?:{words})(?!\w)", text)) and any(
        re.search(p, text) for p in cfg["messenger_patterns"]
    )


def _snapshot_rows(
    facts, brands, cfg: dict, has_brand: bool
) -> tuple[list[tuple[str, float]], list[tuple[str, str, float]], float]:
    """B rows for a brand the page shows on a non-official domain, R rows for a form asking for card / code / Emirates ID / password.
    A hotlink to an official site counts only next to other brand evidence; the third value is its points, which never lift a domain out of NOISE."""
    ok = {f.type: f.value for f in facts if f.type.startswith("snapshot_") and f.status == "ok"}
    b_rows, r_rows = [], []
    shown = ok.get("snapshot_brand")
    if shown:
        name = next((b.name.split(" (")[0] for b in brands if b.id == shown["brand"]), shown["brand"])
        logo = bool(set(shown["via"]) & {"logo", "favicon", "page"})
        b_rows.append(
            (
                f"page shows {name} {'logo' if logo else 'name'} on a non-official domain",
                cfg["page_brand_logo" if logo else "page_brand_name"],
            )
        )
    page = ok.get("snapshot_page") or {}
    hot = 0.0
    if page.get("hotlinks") and (has_brand or shown):
        hot = cfg["hotlink_official"]
        b_rows.append((f"page loads files from {', '.join(page['hotlinks'])} (official site)", hot))
    if page.get("exfil"):
        r_rows.append(
            (
                "exfil",
                f"page contacts {', '.join(page['exfil'])} (a channel for sending stolen data)",
                cfg["exfil_channel"],
            )
        )
    if _offers_work_via_messenger(page, cfg):
        r_rows.append(
            ("offer", "page offers jobs or visas and asks to contact via WhatsApp/Telegram", cfg["offer_messenger"])
        )
    asks = (ok.get("snapshot_form") or {}).get("asks", [])
    if set(asks) - {"password"}:
        r_rows.append(("form", "page asks for " + ", ".join(a for a in asks if a != "password"), cfg["asks_card_otp"]))
    elif asks:
        r_rows.append(("form", "page asks for a password", cfg["asks_password"]))
    return b_rows, r_rows, hot


def _guards(look: dict | None, brands, edges, fqdn, neighbours, url_paths, verdict, cfg: dict) -> list[str]:
    guards = []
    if (
        look
        and look.get("method") in ("homoglyph", "idn")
        and len(look.get("keyword", "")) >= cfg["g1_min_keyword_len"]
    ):
        guards.append("G1")
    if any(e.strength >= cfg["edge_min_strength"] and (e.b if e.a == fqdn else e.a) in neighbours for e in edges):
        guards.append("G2")
    brand = next((b for b in brands if look and b.id == look.get("brand")), None)
    if brand and url_paths:
        names = {w for w in re.split(r"[^a-z0-9]+", brand.name.lower()) if len(w) >= cfg["g3_min_name_len"]} | {
            brand.official_domains[0].split(".")[0]
        }
        names = {n for n in names if len(n) >= cfg["g3_min_name_len"]}
        if any(set(re.split(r"[/\-_.?=&]+", path.lower())) & names for path in url_paths):
            guards.append("G3")
    if verdict is not None:
        guards.append("G4")
    return guards


def assess(
    fqdn,
    facts,
    edges,
    latest_verdict,
    confirmed_neighbours,
    brands,
    weights,
    url_paths=(),
    feed_neighbours=(),
    parked_peers=0,
) -> Assessment:
    """weights = the whole scoring.yaml; url_paths = OpenPhish URL paths of this host (guard G3 never looks at the host);
    confirmed_neighbours = analyst-confirmed scam domains, feed_neighbours = domains in a phishing list (edges come from graph.py)."""
    if is_official(fqdn, brands):
        return Assessment(
            0, 0.0, 0, len(_CHECKS), "OFFICIAL", ["OFFICIAL_DOMAIN"], {"band": "OFFICIAL"}, [], weights["rule_version"]
        )
    bands, brand_cfg, risk_cfg = weights["bands"], weights["points"]["brand"], weights["points"]["risk"]
    lookalikes = [fact for fact in facts if fact.type == "lookalike" and fact.status == "ok"]
    short_max, priors = weights["lookalike"]["context_keyword_max_len"], {b.id: b.prior_points for b in brands}
    best = max(
        (
            (
                _brand_fit(
                    fqdn,
                    f.value,
                    brand_cfg,
                    set(weights["foreign_brands"]),
                    short_max,
                    priors.get(f.value.get("brand"), {}),
                ),
                f,
            )
            for f in lookalikes
        ),
        key=lambda item: sum(points for _, points in item[0][0]),
        default=None,
    )
    (b_rows, neg, flags), look = (best[0], best[1].value) if best else (([], {}, []), None)
    r_rows, r_flags = _risk(
        fqdn,
        facts,
        look,
        edges,
        confirmed_neighbours,
        feed_neighbours,
        risk_cfg,
        weights["guards"]["edge_min_strength"],
        weights["edge"]["min_strength"],
    )
    stale = next(
        (f for f in facts if f.type == "lookalike" and f.status == "missing" and f.error), None
    )  # the intake brand hit no longer matches
    # a name-only page hit (often a block page quoting its own host) must not revive a brand the name no longer earns
    newest = max(
        (f for f in facts if f.type in ("snapshot_page", "snapshot_blocked")), key=lambda f: f.id or 0, default=None
    )  # a later failed snapshot cancels an old "parked"
    page = newest.value if newest and newest.type == "snapshot_page" and newest.status == "ok" else None
    parked = bool(
        page and page.get("parked")
    )  # a for-sale / parking page names the domain itself: its name-only "brand on page" is no evidence (talabat.xyz)
    shown = next((f.value for f in reversed(facts) if f.type == "snapshot_brand" and f.status == "ok"), None)
    shown_brand = next((b for b in brands if shown and b.id == shown.get("brand")), None)
    own = {_registrable(fqdn), _registrable(urlsplit((page or {}).get("final_url") or "").hostname or "")}
    title, text = (page or {}).get("title") or "", (page or {}).get("text") or ""
    echo = bool(
        page
        and shown_brand
        and page_brand_names(title, text, (), shown_brand, weights["snapshot"])
        and not page_brand_names(title, text, own, shown_brand, weights["snapshot"])
    )  # facts stored before the own-address cut: the name was only the host
    page_facts = [
        f
        for f in facts
        if not ((stale and not look) or parked or echo)
        or not (f.type == "snapshot_brand" and f.value.get("via") == ["name"])
    ]
    if len(page_facts) < len(facts):
        flags = [*flags, "PAGE_BRAND_NOT_COUNTED"]  # the card must not list a page hit the score left out
    snap_b, snap_r, hot = _snapshot_rows(
        page_facts, brands, weights["snapshot"], bool(look) and look.get("method") != "smishing_pattern"
    )
    b_rows, r_rows = b_rows + snap_b, r_rows + snap_r
    b, r = sum(points for _, points in b_rows), sum(points for *_, points in r_rows)
    b_noise = b - hot  # a hotlink is not evidence that the name is a brand-fit
    r_ev = sum(points for kind, _, points in r_rows if kind in _RISK_EVIDENCE)
    guards = _guards(look, brands, edges, fqdn, confirmed_neighbours, url_paths, latest_verdict, weights["guards"])
    done = {name for name, types in _CHECKS.items() if any(f.type in types and f.status != "error" for f in facts)}
    coverage = sum(weights["beta"][name] for name in done) / sum(weights["beta"].values())

    soft = {k: v for k, v in neg.items() if k != "B10"}  # a non-UAE brand is still phishing: it stays in the queue
    if latest_verdict is not None and latest_verdict.verdict != "unclear":
        band, reason = "ANALYST_" + latest_verdict.verdict.upper(), "analyst verdict"
    elif soft and b_noise < bands["brand_min"] and not guards:
        band, reason = "NOISE", next(iter(soft.values()))
    elif (
        not look
        and stale
        and b_noise < bands["brand_min"]
        and not any(kind in ("feed", "edge") for kind, _, _ in r_rows)
        and not guards
    ):  # a listed or scam-linked name stays up
        band, reason = "NOISE", stale.error
    elif (
        look
        and look.get("position") == "registrable"
        and r_ev == 0
        and b_noise < bands["brand_strong"]
        and not guards
        and any(kind == "age" and points < 0 for kind, _, points in r_rows)
    ):
        band, reason = "NOISE", "old established domain, weak brand-fit, no risk evidence"
    elif coverage < weights["thresholds"]["min_coverage"]:
        band, reason = "NEED_MORE_DATA", "too few checks answered"
    elif (
        b + r >= bands["t_further"]
        and not neg
        and (b >= bands["brand_strong"] or (b >= bands["brand_min"] and r >= bands["r_strong"]))
    ):
        band, reason = "FURTHER", "enough brand-fit and risk evidence"
    elif r < bands["r_gray"] and b + r < bands["t_low"]:
        band, reason = "GRAY_LOW", "little evidence yet, re-checked at 24 h"
    else:
        band, reason = "GRAY", "some evidence, needs an analyst"
    if look and look.get("method") == "smishing_pattern" and band in ("GRAY", "GRAY_LOW"):
        reason = "Smishing pattern — target unclear"
    if band == "GRAY" and parked and not snap_r:
        band, reason = "GRAY_LOW", "Parked domain (ad page), no phishing page yet — snapshot again later"
    elif (
        band == "GRAY"
        and newest is None
        and parked_peers >= weights["snapshot"]["parked_peers_min"]
        and not guards
        and not any(kind in ("feed", "edge") for kind, _, _ in r_rows)
    ):  # no own snapshot yet (its own decides instead); a listed or scam-linked name stays up
        band, reason = (
            "GRAY_LOW",
            f"Same IP as {parked_peers} parked domains (ad pages) — likely the same parking farm; snapshot when the budget allows",
        )
    young = _young(facts, weights["generic"]["max_age_days"])
    strong_r = [
        row for row in snap_r if row[0] == "exfil" or row[1] != "page asks for a password"
    ]  # a password alone is every casino / forum login
    if (
        band in ("GRAY", "GRAY_LOW", "NEED_MORE_DATA")
        and strong_r
        and not snap_b
        and (not look or look.get("brand") is None)
        and young
    ):
        band, reason = (
            "GRAY",
            "Brand not identified, but the domain is new and " + " and ".join(label for _, label, _ in strong_r),
        )
        flags.append("GENERIC_PHISHING")
    elif (
        look
        and look.get("method") == "generic_name"
        and not young
        and band == "GRAY"
        and not guards
        and not any(kind in ("feed", "edge") for kind, _, _ in r_rows)
    ):
        band, reason = (
            "GRAY_LOW",
            "Old or undated domain, no brand identified: a form alone is not enough",
        )  # an old site asking for a card is usually a shop
    breakdown = [_fmt(points, label) for label, points in b_rows] + [_fmt(points, label) for _, label, points in r_rows]
    if not band.startswith("ANALYST_") and is_regional_official(fqdn, brands):
        if any(
            kind in ("feed", "edge") for kind, _, _ in r_rows
        ):  # listed in a phishing feed or linked to a scam: keep the normal band
            if band == "FURTHER":
                band, reason = "GRAY", "regional site of the brand outside the UAE: an analyst decides"
        else:
            band, reason = (
                "GRAY_LOW",
                "Same name as the official site on a country domain — likely the brand's own regional site; an analyst confirms",
            )
    state = band if band.startswith("ANALYST_") else _STATE[band]
    all_flags = [*flags, *r_flags, *[f"NEG:{k}" for k in neg], *[f"GUARD:{g}" for g in guards]]
    if band in ("GRAY", "GRAY_LOW"):
        all_flags.append(band)
    components = {
        "B": b,
        "R": r,
        "P": b + r,
        "band": band,
        "reason": reason,
        "breakdown": breakdown,
        "checks": len(done),
    }
    return Assessment(
        min(max((b + r) / bands["p_scale"], 0), 1),
        round(coverage, 2),
        len(done),
        len(_CHECKS),
        state,
        all_flags,
        components,
        [f.id for f in lookalikes if hasattr(f, "id")],
        weights["rule_version"],
    )
