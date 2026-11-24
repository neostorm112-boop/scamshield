import yaml

from scamshield.config import CONFIG_DIR
from scamshield.contracts import FactRow

SCORING = yaml.safe_load((CONFIG_DIR / "scoring.yaml").read_text(encoding="utf-8"))
SHARED = yaml.safe_load((CONFIG_DIR / "shared_infra.yaml").read_text(encoding="utf-8"))
STAMP = "2026-11-20T10:00:00Z"
ARAMEX = [
    "aramex-b09d96.ingress-bonde.ewp.live",
    "aramex-b3dbea.ingress-daribow.ewp.live",
    "aramex-b9833c.ingress-earth.ewp.live",
]


class Ids:
    n = 0

    @classmethod
    def row(cls, type_, value, source="dns"):
        cls.n += 1
        return FactRow(type_, value, source, None, STAMP, "ok", id=cls.n)


def _domain(ips=(), asn=None, ns=(), look=True, registrar=None, created=None):
    facts = [Ids.row("lookalike", {"brand": "aramex"}, "lookalike")] if look else []
    if ips:
        facts.append(Ids.row("dns_a", {"records": list(ips)}))
        facts += [Ids.row("ip_asn", {"ip": ip, "asn": asn}, "asn") for ip in ips if asn]
    if ns:
        facts.append(Ids.row("dns_ns", {"records": list(ns)}))
    if registrar:
        facts += [Ids.row("registrar", {"name": registrar}, "rdap"), Ids.row("created_at", {"date": created}, "rdap")]
    return facts


def _graph(domains, fqdn, scoring=SCORING):
    from scamshield.graph import subgraph

    return subgraph(domains, fqdn, scoring, SHARED)


def test_aramex_cluster_linked_by_hostname_pattern_with_reason_and_evidence():
    domains = {name: _domain(ips=["198.51.100.8"], asn=22612) for name in ARAMEX}

    edges = _graph(domains, ARAMEX[0])

    template = [e for e in edges if e.feature == "name_template"]
    assert {frozenset((e.a, e.b)) for e in template} == {
        frozenset(p) for p in [(ARAMEX[0], ARAMEX[1]), (ARAMEX[0], ARAMEX[2]), (ARAMEX[1], ARAMEX[2])]
    }
    assert all(
        e.level == "strong"
        and e.strength >= 0.5
        and "aramex-<hex>" in e.sentence
        and "ewp.live" in e.sentence
        and e.evidence_ids
        for e in template
    )
    ip = [e for e in edges if e.feature == "ip"]
    assert ip and all(e.level == "medium" and e.evidence_ids for e in ip)


def test_two_cloudflare_sites_are_not_linked():
    domains = {
        name: _domain(ips=["104.21.5.5"], asn=13335, ns=["ada.ns.cloudflare.com"])
        for name in ("a-shop.example", "b-shop.example")
    }

    assert _graph(domains, "a-shop.example") == []


def test_shared_hosting_platform_subdomains_are_not_linked():
    domains = {
        name: _domain(ips=["198.51.100.9"], asn=64500)
        for name in ("aramex-1a2b3c4d.pages.dev", "aramex-5e6f7a8b.pages.dev")
    }

    assert _graph(domains, "aramex-1a2b3c4d.pages.dev") == []


def test_shared_ip_on_a_non_shared_host_is_medium():
    domains = {name: _domain(ips=["198.51.100.8"], asn=64500, look=False) for name in ("one.example", "two.example")}

    edges = _graph(domains, "one.example")

    assert [(e.feature, e.level) for e in edges] == [("ip", "medium")]


def test_rare_name_server_is_strong_and_popular_one_is_downgraded():
    names = [f"site-{chr(97 + i)}.example" for i in range(SCORING["edge"]["popular_max"] + 1)]
    rare = {n: _domain(ns=["ns.rare-host.net"], look=False) for n in names[:3]}
    popular = {n: _domain(ns=["ns.rare-host.net"], look=False) for n in names}

    assert {e.level for e in _graph(rare, names[0])} == {"strong"}
    downgraded = _graph(popular, names[0])
    assert {e.level for e in downgraded} == {"medium"} and "popular" in downgraded[0].sentence


def test_same_registrar_same_day_is_medium_only_for_registrable_names():
    domains = {
        n: _domain(registrar="Reg Inc", created="2026-11-19T01:00:00Z", look=False) for n in ("one.com", "two.com")
    }
    domains["x.host.com"] = _domain(registrar="Reg Inc", created="2026-11-19T05:00:00Z", look=False)

    edges = _graph(domains, "one.com")

    assert [(e.b, e.feature, e.level) for e in edges] == [("two.com", "registrar", "medium")]
    assert "Reg Inc | 2026-11-19" in edges[0].sentence


def test_two_hops_and_node_limit():
    domains = {
        "a.example": _domain(ips=["198.51.100.1"], look=False),
        "b.example": _domain(ips=["198.51.100.1", "198.51.100.2"], look=False),
        "c.example": _domain(ips=["198.51.100.2", "198.51.100.3"], look=False),
        "d.example": _domain(ips=["198.51.100.3"], look=False),
    }

    assert {n for e in _graph(domains, "a.example") for n in (e.a, e.b)} == {"a.example", "b.example", "c.example"}
    tiny = {**SCORING, "edge": {**SCORING["edge"], "max_nodes": 2}}
    assert {n for e in _graph(domains, "a.example", tiny) for n in (e.a, e.b)} == {"a.example", "b.example"}


def test_card_shows_neighbours_with_reason_and_evidence_and_no_cloudflare_link(tmp_path, monkeypatch):
    import json
    import sqlite3

    from fastapi.testclient import TestClient

    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    with TestClient(create_app(background=False)) as client:
        conn = sqlite3.connect(tmp_path / "scamshield.db")
        for name, ip in [
            (ARAMEX[0], "198.51.100.8"),
            (ARAMEX[1], "198.51.100.9"),
            ("cf-one.com", "104.21.5.5"),
            ("cf-two.com", "104.21.5.5"),
        ]:
            domain_id = conn.execute(
                "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by) VALUES (?, ?, ?, 'manual')",
                (name, name, STAMP),
            ).lastrowid
            rows = [
                ("lookalike", {"brand": "aramex"}, "lookalike"),
                ("dns_a", {"records": [ip]}, "dns"),
                ("ip_asn", {"ip": ip, "asn": 13335 if ip.startswith("104") else 22612}, "asn"),
            ]
            conn.executemany(
                "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, ?, ?, ?, ?, 'ok')",
                [(domain_id, t, json.dumps(v), s, STAMP) for t, v, s in rows],
            )
        conn.commit()

        aramex, cloudflare = client.get(f"/d/{ARAMEX[0]}").text, client.get("/d/cf-one.com").text

    assert (
        ARAMEX[1] in aramex and "Same hostname pattern aramex-&lt;hex&gt;.ewp.live" in aramex and "14:00 GST" in aramex
    )
    assert 'id="graph-data"' not in cloudflare and "No links found" in cloudflare


def test_parked_peers_count_domains_on_the_same_parking_ip_but_not_on_shared_hosting(tmp_path, monkeypatch):
    """A live run: 104 brand-combo .ph names on one parking IP; snapshots of a few say "parked", the rest inherit it by IP."""
    import json
    import sqlite3

    from fastapi.testclient import TestClient

    from scamshield import graph
    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    with TestClient(create_app(background=False)):
        pass
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.row_factory = sqlite3.Row
    park, cf = ("162.4.84.242", 154653), ("104.21.5.5", 13335)
    rows = [
        ("p1.ph", park, {"parked": "parklogic.com"}),
        ("p2.ph", park, {"parked": "parklogic.com"}),
        ("p3.ph", park, {"title": "shop"}),  # p3: real page, not parked
        ("new.ph", park, None),
        ("p4.ph", park, "parked-then-live"),
        ("cf-a.com", cf, {"parked": "parklogic.com"}),
        ("cf-b.com", cf, {"parked": "parklogic.com"}),
        ("cf-new.com", cf, None),
    ]
    for name, (ip, asn), page in rows:
        domain_id = conn.execute(
            "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by) VALUES (?, ?, ?, 'ct_tiled')",
            (name, name, STAMP),
        ).lastrowid
        snaps = (
            [
                ("snapshot_page", {"parked": "parklogic.com"}, "snapshot"),
                ("snapshot_blocked", {"reason": "x"}, "snapshot"),
            ]
            if page == "parked-then-live"
            else [("snapshot_page", page, "snapshot")]
            if page
            else []
        )
        facts = [
            ("dns_a", {"records": [ip]}, "dns"),
            ("ip_asn", {"ip": ip, "asn": asn}, "asn"),
            *snaps,
        ]  # p4: an old "parked" is cancelled by a newer snapshot
        conn.executemany(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, ?, ?, ?, ?, 'ok')",
            [(domain_id, t, json.dumps(v), s, STAMP) for t, v, s in facts],
        )
    conn.commit()

    assert graph.inputs_for_assessment(conn, "new.ph", SCORING, SHARED)[3] == 2
    assert graph.inputs_for_assessment(conn, "p1.ph", SCORING, SHARED)[3] == 1  # itself is not its own peer
    assert (
        graph.inputs_for_assessment(conn, "cf-new.com", SCORING, SHARED)[3] == 0
    )  # Cloudflare IP: millions of unrelated sites
    conn.execute("UPDATE domains SET state = 'REVIEW'")
    assert [name for _, name in graph.unsnapshotted_ip_peers(conn, "p1.ph", SCORING, SHARED)] == [
        "new.ph"
    ]  # re-scored when p1 turns out parked
    assert graph.unsnapshotted_ip_peers(conn, "cf-a.com", SCORING, SHARED) == []


def test_auto_snapshot_takes_gray_before_gray_low(tmp_path, monkeypatch):
    import json
    import sqlite3

    from fastapi.testclient import TestClient

    from scamshield import snapshot
    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    with TestClient(create_app(background=False)):
        pass
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.row_factory = sqlite3.Row
    for name, seen, band in [
        ("gray.ph", "2026-11-20T10:00:00Z", "GRAY"),
        ("low-newer.ph", "2026-11-20T11:00:00Z", "GRAY_LOW"),
    ]:
        domain_id = conn.execute(
            "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state) VALUES (?, ?, ?, 'ct_tiled', 'REVIEW')",
            (name, name, seen),
        ).lastrowid
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, 'dns_a', ?, 'dns', ?, 'ok')",
            (domain_id, json.dumps({"records": ["198.51.100.8"]}), STAMP),
        )
        conn.execute(
            "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) VALUES (?, 'v', 0.3, 1, 'REVIEW', ?, '{}', '[]', ?)",
            (domain_id, json.dumps([band]), STAMP),
        )
    conn.commit()
    assert snapshot._next_auto(conn) == "gray.ph"


def test_empty_or_parked_pages_are_snapshotted_again_on_the_schedule(tmp_path, monkeypatch):
    """Kits are often uploaded 6-48 h after the certificate: re-snapshot empty / parked / failed pages at +6 h, +24 h, +72 h, then stop."""
    import json
    import sqlite3
    from datetime import UTC, datetime

    from fastapi.testclient import TestClient

    from scamshield import snapshot
    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    with TestClient(create_app(background=False)):
        pass
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.row_factory = sqlite3.Row
    now = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)

    def add(name, band, snaps, seen="2026-11-20T10:00:00Z"):
        domain_id = conn.execute(
            "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state) VALUES (?, ?, ?, 'ct_tiled', 'REVIEW')",
            (name, name, seen),
        ).lastrowid
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, 'dns_a', ?, 'dns', ?, 'ok')",
            (domain_id, json.dumps({"records": ["198.51.100.8"]}), STAMP),
        )
        conn.execute(
            "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) VALUES (?, 'v', 0.3, 1, 'REVIEW', ?, '{}', '[]', ?)",
            (domain_id, json.dumps([band]), STAMP),
        )
        for kind, value, status, at in snaps:
            conn.execute(
                "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (?, ?, ?, 'snapshot', ?, ?)",
                (domain_id, kind, json.dumps(value), at, status),
            )
        conn.commit()

    def pick():
        return snapshot._next_auto(conn, [6, 24, 72], now)

    parked = ("snapshot_page", {"title": "Redirecting...", "text": "", "parked": "parklogic.com"}, "ok")
    add("too-early.ph", "GRAY_LOW", [(*parked, "2026-11-21T07:00:00Z")])  # 5 h after the 1st: not yet
    add(
        "real-page.com",
        "GRAY",
        [("snapshot_page", {"title": "Shop", "text": "Buy shoes"}, "ok", "2026-11-19T00:00:00Z")],
    )  # a real page is judged, no re-snapshot
    add("done.ph", "GRAY", [(*parked, f"2026-11-1{d}T00:00:00Z") for d in range(4)])  # 4 snapshots: schedule finished
    add(
        "sinkhole.top", "GRAY", [("snapshot_blocked", {"reason": "PRIVATE_ADDRESS"}, "ok", "2026-11-20T00:00:00Z")]
    )  # the safety check would refuse again
    add(
        "third.top",
        "GRAY",
        [(*parked, "2026-11-17T00:00:00Z"), (*parked, "2026-11-18T00:00:00Z"), (*parked, "2026-11-19T00:00:00Z")],
    )  # 3rd taken 60 h ago, next at 72 h
    assert pick() is None
    add(
        "blocked-kit.top", "GRAY", [("snapshot_blocked", {"reason": "download"}, "ok", "2026-11-21T06:00:00Z")]
    )  # exactly 6 h ago: due
    assert pick() == "blocked-kit.top"
    conn.execute(
        "INSERT INTO feedback (domain_id, verdict, reason, analyst, created_at) SELECT id, 'legit', 'x', 'a', ? FROM domains WHERE fqdn = 'blocked-kit.top'",
        (STAMP,),
    )
    conn.commit()
    assert pick() is None  # an analyst decision ends automatic snapshots
    add(
        "blank.top", "GRAY", [("snapshot_page", {"title": "", "text": " "}, "ok", "2026-11-21T05:00:00Z")]
    )  # blank, 7 h after the 1st: due
    add(
        "failed.top",
        "GRAY",
        [
            ("snapshot_page", {}, "error", "2026-11-20T09:00:00Z"),
            ("snapshot_page", {}, "error", "2026-11-20T10:00:00Z"),
        ],
    )  # 2nd failed 26 h ago: due 1 h before blank.top
    assert pick() == "failed.top"
    add("new-low.ph", "GRAY_LOW", [], seen="2026-11-21T11:00:00Z")
    assert pick() == "failed.top"  # a due re-snapshot goes before a never-snapshotted GRAY_LOW name
    add("new-gray.top", "GRAY", [], seen="2026-11-21T11:00:00Z")
    assert pick() == "new-gray.top"  # a never-snapshotted GRAY name goes first
    assert snapshot._next_auto(conn, [], now) == "new-gray.top"
