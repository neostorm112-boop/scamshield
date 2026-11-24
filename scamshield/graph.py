"""Link graph: edges between domains from shared infrastructure. Every edge has a level (strong / medium; weak is dropped), a reason and the facts it rests on."""

from __future__ import annotations

import ipaddress
import json
import re
from collections import defaultdict

from scamshield import db
from scamshield.contracts import Edge, FactRow
from scamshield.netsafe import icann_registrable_of

_LEVELS = ("weak", "medium", "strong")
_TYPES = ("dns_a", "dns_ns", "ip_asn", "registrar", "created_at", "lookalike", "in_feed", "relative_link")
_TITLES = {
    "ns": "same name server",
    "ip": "same IP",
    "name_template": "same hostname pattern",
    "registrar": "same registrar + day",
    "script": "same script",
    "script_3p": "same third-party script",
    "panel": "same data panel",
}
# find relatives (urlscan): the site's own kit file / panel = strong; a file from another host and the same IP = medium, as for DNS
_RELATIVE_LEVEL = {"script": "strong", "panel": "strong", "script_3p": "medium", "ip": "medium"}
_KIT = (
    "script",
    "panel",
)  # own kit files only (script_3p keeps popular_max); popular only above edge.popular_max_kit: one gang's kit sits on tens of its own domains (46)


def _ok(facts, type_):
    return [f for f in facts if f.type == type_ and f.status == "ok"]


def _template(label: str, min_literal: int) -> str | None:
    """`aramex-b09d96` -> `aramex-<hex>`; only when a substitution happened and enough fixed letters remain to mean something."""
    out = re.sub(r"\d{2,}", "<n>", re.sub(r"[0-9a-f]{6,}", "<hex>", label))
    return out if out != label and len(re.sub(r"<hex>|<n>|[^a-z]", "", out)) >= min_literal else None


def _not_linkable_ip(value: str, nets) -> bool:
    try:
        return any(ipaddress.ip_address(value) in net for net in nets)
    except ValueError:
        return True


def _keys(fqdn: str, facts, cfg: dict, shared: dict) -> list[tuple[str, str, str, list[int]]]:
    """(feature, value, level, fact ids) this domain can be linked by. Platform subdomains, CDN, parking and sinkholes give none."""
    if any(fqdn == s or fqdn.endswith(f".{s}") for s in shared["host_suffixes"]):
        return []
    keys = []
    for fact in _ok(facts, "dns_ns"):
        keys += [
            ("ns", ns.lower(), "strong", [fact.id])
            for ns in fact.value.get("records", [])
            if not any(s in ns.lower() for s in shared["ns_suffixes"])
        ]
    asn_of = {f.value["ip"]: f for f in _ok(facts, "ip_asn") if "ip" in f.value and "asn" in f.value}
    nets = [ipaddress.ip_network(c) for c in shared["cidrs"]]
    for fact in _ok(facts, "dns_a"):
        for ip in fact.value.get("records", []):
            asn = asn_of.get(ip)
            if (asn and asn.value["asn"] in shared["asns"]) or any(ipaddress.ip_address(ip) in net for net in nets):
                continue
            keys.append(("ip", ip, "medium", [fact.id, *([asn.id] if asn else [])]))
    registrable = icann_registrable_of(fqdn)
    template = _template(fqdn.split(".")[0], cfg["pattern_min_literal"])
    if template and registrable:
        look = next(iter(_ok(facts, "lookalike")), None)
        tail = registrable if fqdn != registrable else fqdn.split(".", 1)[1]
        keys.append(("name_template", f"{template}.{tail}", "strong", [look.id] if look else []))
    registrar, created = next(iter(_ok(facts, "registrar")), None), next(iter(_ok(facts, "created_at")), None)
    if (
        fqdn == registrable and registrar and created and registrar.value.get("name") and created.value.get("date")
    ):  # a subdomain's age is its host's
        keys.append(
            (
                "registrar",
                f"{registrar.value['name']} | {created.value['date'][:10]}",
                "medium",
                [registrar.id, created.id],
            )
        )
    for fact in _ok(
        facts, "relative_link"
    ):  # a shared script hash / panel / IP seen by urlscan ("find relatives"); never the official favicon
        feature, value = fact.value.get("feature"), str(fact.value.get("value") or "")
        if feature in _RELATIVE_LEVEL and value and not (feature == "ip" and _not_linkable_ip(value, nets)):
            keys.append((feature, value, _RELATIVE_LEVEL[feature], [fact.id]))
    merged: dict[tuple[str, str], tuple[str, str, str, list[int]]] = {}
    for (
        feature,
        value,
        level,
        ids,
    ) in keys:  # one key per (feature, value): the same IP from DNS and from urlscan is one link
        old = merged.get((feature, value))
        merged[feature, value] = (
            (feature, value, level, ids)
            if old is None
            else (feature, value, old[2], [*old[3], *[i for i in ids if i not in old[3]]])
        )
    return list(merged.values())


def _sentence(feature: str, value: str, count: int, popular: bool) -> str:
    text = {
        "ns": f"Same name server {value}",
        "ip": f"Same IP {value} on a non-shared host",
        "name_template": f"Same hostname pattern {value}",
        "registrar": f"Same registrar and registration day ({value})",
        "script": f"Same script / style file (SHA-256 {value[:12]}…)",
        "script_3p": f"Same third-party script / style file (SHA-256 {value[:12]}…)",
        "panel": f"Same data panel {value} (the page's WebSocket server)",
    }[feature]
    return f"{text}, shared by {count} domains in our database" + (" (popular: downgraded)" if popular else "")


def subgraph(domains: dict[str, list[FactRow]], fqdn: str, scoring: dict, shared: dict) -> list[Edge]:
    """Edges within cfg.hops of fqdn, at most cfg.max_nodes nodes; strongest neighbours first."""
    cfg = scoring["edge"]
    keys = {name: _keys(name, facts, cfg, shared) for name, facts in domains.items()}
    members, evidence = defaultdict(list), {}
    for name, found in keys.items():
        for feature, value, _, ids in found:
            members[feature, value].append(name)
            evidence[name, feature, value] = ids

    def edges_of(node):
        for feature, value, level, _ in keys[node]:
            group = members[feature, value]
            popular = (
                len(group) > cfg["popular_max_kit" if feature in _KIT else "popular_max"]
            )  # a name server / IP / pattern shared this widely says little
            level = _LEVELS[max(_LEVELS.index(level) - 1, 0)] if popular else level
            if cfg["strength"][level] < cfg["min_strength"]:
                continue
            for other in group:
                if other != node:
                    a, b = sorted((node, other))
                    yield Edge(
                        a,
                        b,
                        feature,
                        value,
                        round(1 / len(group), 3),
                        cfg["strength"][level],
                        _sentence(feature, value, len(group), popular),
                        [*evidence[a, feature, value], *evidence[b, feature, value]],
                        level,
                    )

    nodes, frontier, found = {fqdn}, [fqdn], {}
    if fqdn not in keys:
        return []
    for _ in range(cfg["hops"]):
        reached = []
        for node in frontier:
            for edge in sorted(edges_of(node), key=lambda e: -e.strength):
                other = edge.b if edge.a == node else edge.a
                if other not in nodes:
                    if len(nodes) >= cfg["max_nodes"]:
                        continue
                    nodes.add(other)
                    reached.append(other)
                found[edge.a, edge.b, edge.feature, edge.shared_value] = edge
        frontier = reached
    return list(found.values())


def load(conn) -> dict[str, list[FactRow]]:
    """Current facts of every domain, only the types the graph reads."""
    result = {}
    for domain in conn.execute("SELECT id, fqdn FROM domains").fetchall():
        result[domain["fqdn"]] = [
            FactRow(
                r["type"],
                json.loads(r["value_json"]),
                r["source"],
                r["observed_at"],
                r["fetched_at"],
                r["status"],
                r["error"],
                r["data_mode"],
                r["raw_ref"],
                r["id"],
                r["domain_id"],
            )
            for r in db.current_facts(conn, domain["id"])
            if r["type"] in _TYPES
        ]
    return result


def _parked_peers(conn, domains: dict[str, list[FactRow]], fqdn: str, cfg: dict, shared: dict) -> int:
    """Other domains on one of fqdn's IPs (shared hosting / CDN excluded, as for edges) whose newest snapshot shows a parked page.
    Popular IPs count too: a parking farm puts hundreds of names on one address, which is exactly what this detects."""
    ips = {value for feature, value, *_ in _keys(fqdn, domains.get(fqdn, []), cfg, shared) if feature == "ip"}
    if not ips:
        return 0
    parked = [
        r[0]
        for r in conn.execute(
            """SELECT d.fqdn FROM domains d JOIN facts f ON f.id = (SELECT MAX(id) FROM facts WHERE domain_id = d.id AND type IN ('snapshot_page', 'snapshot_blocked'))
        WHERE f.type = 'snapshot_page' AND f.status = 'ok' AND json_extract(f.value_json, '$.parked') IS NOT NULL AND d.fqdn != ?""",
            (fqdn,),
        )
    ]
    return sum(
        1
        for name in parked
        if ips & {value for feature, value, *_ in _keys(name, domains.get(name, []), cfg, shared) if feature == "ip"}
    )


def unsnapshotted_ip_peers(conn, fqdn: str, scoring: dict, shared: dict) -> list[tuple[int, str]]:
    """(id, fqdn) of queued domains on one of fqdn's IPs (shared hosting excluded) with no snapshot yet: re-scored when fqdn turns out parked."""
    domains, cfg = load(conn), scoring["edge"]
    ips = {value for feature, value, *_ in _keys(fqdn, domains.get(fqdn, []), cfg, shared) if feature == "ip"}
    if not ips:
        return []
    rows = conn.execute(
        """SELECT id, fqdn FROM domains d WHERE d.state = 'REVIEW' AND d.fqdn != ?
        AND NOT EXISTS (SELECT 1 FROM facts WHERE domain_id = d.id AND type LIKE 'snapshot\\_%' ESCAPE '\\')""",
        (fqdn,),
    ).fetchall()
    return [
        (r[0], r[1])
        for r in rows
        if ips & {value for feature, value, *_ in _keys(r[1], domains.get(r[1], []), cfg, shared) if feature == "ip"}
    ]


def inputs_for_assessment(conn, fqdn: str, scoring: dict, shared: dict) -> tuple[list[Edge], list[str], list[str], int]:
    """Direct edges of fqdn, neighbours with an analyst verdict "scam", neighbours listed in a phishing feed (for scoring.assess G2 / R4),
    and how many parked domains share an IP with it."""
    domains = load(conn)
    edges = [e for e in subgraph(domains, fqdn, {**scoring, "edge": {**scoring["edge"], "hops": 1}}, shared)]
    others = {e.b if e.a == fqdn else e.a for e in edges}
    confirmed = [
        o
        for o in others
        if (
            conn.execute(
                "SELECT f.verdict FROM feedback f JOIN domains d ON d.id = f.domain_id WHERE d.fqdn = ? ORDER BY f.id DESC LIMIT 1",
                (o,),
            ).fetchone()
            or [None]
        )[0]
        == "scam"
    ]
    listed = [
        o for o in others if any(f.type == "in_feed" and f.status == "ok" and f.value.get("listed") for f in domains[o])
    ]
    return edges, confirmed, listed, _parked_peers(conn, domains, fqdn, scoring["edge"], shared)


def _relative_label(edge: Edge, fqdn: str, by_id: dict, owner: dict) -> tuple[str, str] | None:
    """("same main.js", "2026-11-19") when the edge rests on a find-relatives fact: the file name and the date of the other site's urlscan scan."""
    found = [by_id[i] for i in edge.evidence_ids if i in by_id and by_id[i].type == "relative_link"]
    if not found:
        return None
    other = [f for f in found if owner[f.id] != fqdn] or found
    date = max(str(f.value.get("scan_date") or f.fetched_at) for f in other)[:10]
    file = str(found[0].value.get("file") or "")[:80]
    name = (
        (f"same {file}" if edge.feature == "script" else f"same third-party {file}")
        if edge.feature in ("script", "script_3p") and file
        else _TITLES[edge.feature]
    )
    return name, date


def card_view(conn, fqdn: str, scoring: dict, shared: dict) -> list[dict]:
    """Edges for the card: reason, level and each fact (E-number, kind, source, time) the edge rests on."""
    domains = load(conn)
    by_id = {f.id: f for facts in domains.values() for f in facts}
    owner = {f.id: name for name, facts in domains.items() for f in facts}
    out = []
    for e in subgraph(domains, fqdn, scoring, shared):
        title, sentence = f"{_TITLES[e.feature]} ({e.level})", e.sentence
        relative = _relative_label(e, fqdn, by_id, owner)
        if relative:
            title, sentence = (
                f"{relative[0]}, urlscan scan of {relative[1]} ({e.level})",
                f"{e.sentence} — urlscan scan of {relative[1]}",
            )
        out.append(
            {
                "a": e.a,
                "b": e.b,
                "title": title,
                "level": e.level,
                "sentence": sentence,
                "evidence": [
                    {"id": i, "type": by_id[i].type, "source": by_id[i].source, "fetched_at": by_id[i].fetched_at}
                    for i in e.evidence_ids
                    if i in by_id
                ],
            }
        )
    return out
