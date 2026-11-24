"""Freshness line on the case (registered -> certificate -> found by us -> listed) and the required reason in Decide."""

import json
import sqlite3
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from scamshield.web import view

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


def _fact(kind, value, status="ok"):
    return {"type": kind, "value": value, "status": status}


def _texts(parts):
    return [f"{p['label']} {p['text']}" for p in parts]


def test_timeline_has_all_parts_in_time_order():
    domain = {"found_by": "ct_tiled", "first_seen_at": "2026-11-22T08:00:00Z"}
    facts = [
        _fact("created_at", {"date": "2026-11-22T05:30:00Z"}),
        _fact("in_feed", {"listed": True, "feeds": ["openphish"], "first_listed_at": "2026-11-22T10:15:00Z"}),
    ]
    parts = view.timeline(domain, facts, "2026-11-22T08:03:00Z", NOW)
    assert _texts(parts) == [
        "Registered 6 h ago",
        "Certificate 22 Nov 12:00 GST",
        "Found by ScamShield 22 Nov 12:03 GST (+3 min after the certificate)",
        "Listed by OpenPhish 22 Nov 14:15 GST",
    ]
    assert [p["lead"] for p in parts] == [False, False, True, False]


def test_timeline_omits_missing_parts():
    domain = {"found_by": "feeds", "first_seen_at": "2026-11-22T08:00:00Z"}
    facts = [
        _fact("created_at", {}),
        _fact("in_feed", {"listed": False, "feeds": []}),
        _fact("certs", {"first_issued": "2026-11-09T07:00:00Z"}, "error"),
    ]
    assert _texts(view.timeline(domain, facts, "2026-11-22T08:03:00Z", NOW)) == ["Found by ScamShield 22 Nov 12:03 GST"]
    assert view.timeline(domain, [], None, NOW) == []


def test_timeline_certificate_from_certs_fact_has_no_gap_text():
    domain = {"found_by": "urlscan", "first_seen_at": "2026-11-22T08:00:00Z"}
    parts = view.timeline(
        domain, [_fact("certs", {"first_issued": "2026-11-09T07:00:00Z"})], "2026-11-22T08:03:00Z", NOW
    )
    assert _texts(parts) == ["Certificate 9 Nov 11:00 GST", "Found by ScamShield 22 Nov 12:03 GST"]


def test_case_page_shows_timeline_and_decide_needs_a_reason(tmp_path, monkeypatch):
    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    with TestClient(create_app(background=False)) as client:
        conn = sqlite3.connect(tmp_path / "scamshield.db")
        conn.execute(
            "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score) VALUES ('t.example', 't.example', '2026-11-20T08:00:00Z', 'ct_tiled', 'REVIEW', 0.4)"
        )
        conn.execute(
            "INSERT INTO jobs (kind, target, payload_json, idem_key, status, created_at) VALUES ('check_domain', 't.example', '{}', 'k', 'done', '2026-11-20T08:02:00Z')"
        )
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (1, 'created_at', ?, 'rdap', '2026-11-20T08:03:00Z', 'ok')",
            (json.dumps({"date": "2026-11-19T20:00:00Z"}),),
        )
        conn.commit()
        page = client.get("/d/t.example").text
        saved = client.post("/d/t.example/feedback", data={"verdict": "scam", "reason": "  "}, follow_redirects=False)
        rows = conn.execute("SELECT count(*) FROM feedback").fetchone()[0]

    assert (
        "Registered" in page
        and "<b>Certificate</b> 20 Nov 12:00 GST" in page
        and "(+2 min after the certificate)" in page
    )
    assert 'name="reason" type="text" required' in page and 'class="save" type="submit" disabled' in page
    assert saved.status_code == 303 and rows == 0


def _ctx(facts, now=NOW):
    domain = {
        "fqdn": "t.example",
        "brand_id": None,
        "state": "REVIEW",
        "risk_score": 0.4,
        "found_by": "feeds",
        "first_seen_at": "2026-11-22T08:00:00Z",
    }
    full = [
        {"id": i, "source": "x", "fetched_at": "2026-11-22T08:00:00Z", "data_mode": "LIVE", "error": None, **f}
        for i, f in enumerate(facts, 1)
    ]
    return view.case_context(domain, full, None, None, {"poll": False, "text": None}, [], {}, now)


def test_reasons_are_real_signals_only_form_first():
    facts = [
        _fact("certs", {"count": 8, "first_issued": "2026-08-25T00:00:00Z", "issuer": "Google Trust Services"}),
        _fact("dns_a", {"records": ["1.2.3.4"]}),
        _fact("registrar", {"name": "X"}),
        _fact("ip_asn", {"asn": 13335, "ip": "1.2.3.4"}),
        _fact("created_at", {"date": "2020-01-01T00:00:00Z"}),
        _fact("search_hit", {"query": "Darb toll payment", "rank": 7}),
        _fact(
            "snapshot_form", {"fields": [{"name": "password", "type": "password"}], "asks": ["emirates_id", "password"]}
        ),
    ]
    reasons = [r["reason"] if r.get("reason") else r["text"] for r in _ctx(facts)["reasons"]]
    assert reasons[0] == "Login page asks for Emirates ID and password"
    assert len(reasons) == 2 and "web search" in reasons[1]
    assert _ctx(facts[:5])["reasons"] == []  # neutral facts never become reasons


def test_registration_date_is_gst_in_reason_and_timeline():
    facts = [_fact("created_at", {"date": "2026-11-15T23:47:37Z"})]  # 16 Nov 03:47 GST
    assert _ctx(facts)["reasons"][0]["text"] == "Registered 6 days ago (16 Nov 2026)"
    assert _texts(view.timeline({"found_by": "urlscan", "first_seen_at": None}, facts, None, NOW)) == [
        "Registered 16 Nov"
    ]


def test_found_after_certificate_within_48_hours_shows_the_gap():
    domain = {"found_by": "urlscan", "first_seen_at": None}
    facts = [_fact("certs", {"first_issued": "2026-11-21T19:18:00Z"})]
    assert (
        _texts(view.timeline(domain, facts, "2026-11-21T19:32:00Z", NOW))[-1]
        == "Found by ScamShield 21 Nov 23:32 GST (+14 min after the certificate)"
    )
    assert (
        "(+"
        not in _texts(
            view.timeline(
                domain, [_fact("certs", {"first_issued": "2026-11-09T19:18:00Z"})], "2026-11-21T19:32:00Z", NOW
            )
        )[-1]
    )


def test_certificate_older_than_registration_is_dropped():
    domain = {"found_by": "urlscan", "first_seen_at": None}
    facts = [
        _fact("created_at", {"date": "2026-11-16T00:00:00Z"}),
        _fact("certs", {"first_issued": "2026-11-09T09:48:00Z"}),
    ]
    parts = _texts(view.timeline(domain, facts, "2026-11-21T19:32:00Z", NOW))
    assert parts == [
        "Registered 16 Nov",
        "Found by ScamShield 21 Nov 23:32 GST (5 days after registration)",
    ]  # 5.8 days: whole days, like every age on the card


def test_gap_after_registration_in_hours_and_not_beyond_30_days():
    domain = {"found_by": "urlscan", "first_seen_at": None}
    near = [_fact("created_at", {"date": "2026-11-21T10:00:00Z"})]
    assert _texts(view.timeline(domain, near, "2026-11-21T19:32:00Z", NOW))[-1].endswith(
        "(9 h after registration)"
    )  # 9.5 h: whole hours
    old = [_fact("created_at", {"date": "2026-09-01T00:00:00Z"})]
    assert "after registration" not in _texts(view.timeline(domain, old, "2026-11-21T19:32:00Z", NOW))[-1]


def test_timeline_date_from_an_earlier_year_shows_the_year():
    """rta.ae in a live run: certspotter first_issued 2025-12-08 rendered as '8 Dec 04:00 GST' on 22 Nov 2026 and read as a future date."""
    domain = {"found_by": "manual", "first_seen_at": "2026-11-22T14:07:49Z"}
    parts = view.timeline(
        domain, [_fact("certs", {"first_issued": "2025-12-08T00:00:00Z"})], "2026-11-22T14:07:49Z", NOW
    )
    assert _texts(parts)[0] == "Certificate 8 Dec 2025 04:00 GST"
    born = [_fact("created_at", {"date": "2019-03-01T00:00:00Z"})]
    assert _texts(view.timeline({"found_by": "manual", "first_seen_at": None}, born, None, NOW)) == [
        "Registered 1 Mar 2019"
    ]
