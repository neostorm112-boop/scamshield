"""Queue views : risk order, low-signal rows apart, one list and one count per view,
controls above the list, a page limit from ui.yaml, and the AI daily cap in the banner."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

NOW = datetime.now(UTC)


def _iso(moment):
    return moment.isoformat().replace("+00:00", "Z")


def _add(conn, fqdn, state, risk, band="GRAY", found_by="feeds", age_h=1, verdict=None):
    conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score) VALUES (?, ?, ?, ?, ?, ?)",
        (fqdn, fqdn, _iso(NOW - timedelta(hours=age_h)), found_by, state, risk),
    )
    conn.execute(
        "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) "
        "VALUES ((SELECT id FROM domains WHERE fqdn = ?), 'v2-points', ?, 1, ?, '[]', ?, '[]', ?)",
        (fqdn, risk, state, json.dumps({"band": band, "reason": "test"}), _iso(NOW)),
    )
    if verdict:
        conn.execute(
            "INSERT INTO feedback (domain_id, verdict, reason, analyst, created_at) VALUES ((SELECT id FROM domains WHERE fqdn = ?), ?, 'test', NULL, ?)",
            (fqdn, verdict, _iso(NOW)),
        )


def _seed(path):
    conn = sqlite3.connect(path)
    _add(conn, "fresh-fifty.com", "REVIEW", 0.50, age_h=1)  # urgency 0.50 x 1.0
    _add(
        conn, "old-sixtytwo.com", "REVIEW", 0.62, age_h=120
    )  # urgency 0.62 x 0.4: was below 50, risk order puts it first
    _add(conn, "top-high.com", "REVIEW_HIGH", 0.96, age_h=200)
    _add(conn, "weak-one.top", "REVIEW", 0.0, band="GRAY_LOW")  # low signal
    _add(conn, "weak-two.shop", "REVIEW", 0.1, band="GRAY_LOW")
    _add(conn, "noise.ac.bd", "NOISE", 0.0, band="NOISE")  # filtered out
    _add(conn, "decided-scam.com", "REVIEW", 0.7, verdict="scam")  # decided
    _add(conn, "base-line.com", "REVIEW", 0.4, found_by="baseline")
    conn.commit()


@pytest.fixture
def client(tmp_path, monkeypatch):
    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    with TestClient(create_app(background=False)) as c:
        _seed(tmp_path / "scamshield.db")
        yield c


def _rows(page: str) -> list[str]:
    body = page.split('id="rows"')[1].split("</ul>")[0].replace("<wbr>", "")
    return [part.split('"')[0] for part in body.split('href="/d/')[1:]]


def _queue(tmp_path):
    from scamshield import config
    from scamshield.web import view

    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.row_factory = sqlite3.Row
    return view.queue(conn, config.load())


def test_queue_is_ordered_by_risk_and_low_signal_rows_are_apart(client, tmp_path):
    q = _queue(tmp_path)
    assert [r["fqdn"] for r in q["todo"]] == ["top-high.com", "old-sixtytwo.com", "fresh-fifty.com"]
    assert [r["fqdn"] for r in q["low"]] == ["weak-two.shop", "weak-one.top"]
    assert [r["fqdn"] for r in q["filtered"]] == ["noise.ac.bd"]
    assert [r["fqdn"] for r in q["decided"]] == ["decided-scam.com"]
    assert [r["fqdn"] for r in q["baseline"]] == ["base-line.com"]
    assert q["count"] == 3


@pytest.mark.parametrize(
    "query, header, rows",
    [
        ("", "3</b> to check", ["top-high.com", "old-sixtytwo.com", "fresh-fifty.com"]),
        ("?low=1", "2</b> low signal", ["weak-two.shop", "weak-one.top"]),
        ("?decided=1", "1</b> decided", ["decided-scam.com"]),
        ("?filtered=1", "1</b> filtered out", ["noise.ac.bd"]),
        ("?baseline=1", "1</b> baseline", ["base-line.com"]),
    ],
)
def test_each_view_shows_its_own_rows_and_count(client, query, header, rows):
    page = client.get("/" + query).text
    assert header in page
    assert [r.split("?")[0] for r in _rows(page)] == rows


def test_view_tabs_carry_counts_and_sit_above_the_list(client):
    page = client.get("/").text
    for label in ("To check (3)", "Low signal (2)", "Decided (1)", "Filtered out (1)", "Baseline (1)"):
        assert label in page
    assert page.index("Filtered out (1)") < page.index('id="rows"') and page.index("Web search") < page.index(
        'id="rows"'
    )


def test_poll_keeps_the_view_and_its_count(client):
    part = client.get("/partials/feed-rows", params={"since": _iso(NOW), "low": 1}).text
    assert [r.split("?")[0] for r in _rows('id="rows"' + part + "</ul>")] == ["weak-two.shop", "weak-one.top"]
    assert '<span id="q-count" hx-swap-oob="true">2</span>' in part


def test_long_view_is_cut_to_the_page_size_from_ui_yaml(client, monkeypatch):
    from scamshield.web import view

    base = view._ui()
    monkeypatch.setattr(view, "_ui", lambda: {**base, "queue_page_rows": 2})
    first = client.get("/").text
    more = client.get("/?rows=4").text
    assert len(_rows(first)) == 2 and "Show 1 more" in first and "rows=4" in first
    assert len(_rows(more)) == 3 and "Show" not in more.split('id="rows"')[1].split("</ul>")[0]


def test_decided_view_keeps_the_latest_decision_first_not_the_highest_risk(client, tmp_path):
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    _add(conn, "older-high.com", "REVIEW", 0.95, verdict="scam")
    _add(conn, "newer-low.com", "REVIEW", 0.30, verdict="legit")
    conn.execute(
        "UPDATE feedback SET created_at = ? WHERE domain_id = (SELECT id FROM domains WHERE fqdn = 'older-high.com')",
        (_iso(NOW - timedelta(hours=5)),),
    )
    conn.execute(
        "UPDATE feedback SET created_at = ? WHERE domain_id = (SELECT id FROM domains WHERE fqdn = 'newer-low.com')",
        (_iso(NOW + timedelta(minutes=5)),),
    )
    conn.commit()
    decided = [r["fqdn"] for r in _queue(tmp_path)["decided"]]
    assert decided.index("newer-low.com") < decided.index("older-high.com")


def test_rows_parameter_is_capped_by_ui_yaml(client, monkeypatch):
    from scamshield.web import view

    base = view._ui()
    monkeypatch.setattr(view, "_ui", lambda: {**base, "queue_page_rows": 1, "queue_page_rows_max": 2})
    page = client.get("/?low=1&rows=100000")
    assert page.status_code == 200 and len(_rows(page.text)) == 2
    for bad in ("abc", "-5", ""):
        page = client.get(f"/?low=1&rows={bad}")
        assert page.status_code == 200 and len(_rows(page.text)) == 1


def test_banner_says_ai_is_paused_by_the_daily_cap(client, tmp_path):
    from scamshield import explain

    assert "AI paused" not in client.get("/partials/banner").text
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.execute(
        "INSERT INTO llm_spend (day, est_usd) VALUES (?, ?)", (explain._today(), explain._cap() - 0.01)
    )  # less than one call left ($4.98 of a $5 cap)
    conn.commit()
    banner = client.get("/partials/banner").text
    assert "AI paused: daily spending limit reached" in banner and "all sources working" not in banner
