import json
import sqlite3

from fastapi.testclient import TestClient

from scamshield import db
from scamshield.app import create_app

T = "2026-11-20T10:00:00Z"


def _setup(
    tmp_path, monkeypatch, *, rdap=True, verdict=None, field="card", state="REVIEW", brand_id=None, fqdn="rta-pay.com"
):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    path = str(tmp_path / "scamshield.db")
    db.init(path)
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score, brand_id) VALUES (?, ?, ?, 'ct_tiled', ?, 0.7, ?)",
        (fqdn, fqdn, T, state, brand_id),
    )
    facts = [
        ("lookalike", {"brand": "rta", "keyword": "rta", "method": "contains"}, "lookalike"),
        ("ip_asn", {"ip": "203.0.113.9", "asn": 64500, "name": "Example Hosting"}, "asn"),
        ("snapshot_page", {"title": "RTA Fines"}, "snapshot"),
        ("snapshot_form", {"fields": [{"name": field, "type": "text"}], "asks": ["card number"]}, "snapshot"),
    ]
    if rdap:
        facts += [
            ("created_at", {"date": "2026-11-18T00:00:00Z"}, "rdap"),
            ("registrar", {"name": "Example Registrar", "abuse_email": "abuse@registrar.example"}, "rdap"),
        ]
    for kind, value, source in facts:
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (1, ?, ?, ?, ?, 'ok')",
            (kind, json.dumps(value), source, T),
        )
    if verdict:
        conn.execute(
            "INSERT INTO feedback (domain_id, verdict, reason, analyst, created_at) VALUES (1, ?, '', NULL, ?)",
            (verdict, T),
        )
    conn.commit()


def test_takedown_text_has_header_evidence_and_no_overclaim(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    with TestClient(create_app(background=False)) as client:
        r = client.get("/d/rta-pay.com/takedown.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    for part in (
        "DRAFT — review before sending",
        "Subject: Abuse report: rta-pay.com",
        "rta.ae",
        f"[Brand check, {T}]",
        f"[Hosting lookup, {T}]",
        f"[Snapshot, {T}]",
        "abuse email: abuse@registrar.example",
        "https://rdap.org/ip/203.0.113.9",
        "appears to impersonate",
        "card number",
    ):
        assert part in r.text
    assert "is a scam" not in r.text and "confirmed by our analyst" not in r.text


def test_takedown_analyst_scam_verdict_says_confirmed(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, verdict="scam")
    with TestClient(create_app(background=False)) as client:
        text = client.get("/d/rta-pay.com/takedown.txt").text
    assert "confirmed by our analyst" in text and "Confirmed by analyst" in text


def test_takedown_unknown_domain_is_404(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    with TestClient(create_app(background=False)) as client:
        for path in ("/d/nope.example/takedown.txt", "/d/nope.example/takedown"):
            r = client.get(path)
            assert r.status_code == 404 and "is not in our database" in r.text


def test_takedown_without_rdap_says_registrar_unknown(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, rdap=False)
    with TestClient(create_app(background=False)) as client:
        r = client.get("/d/rta-pay.com/takedown.txt")
    assert r.status_code == 200 and "Registrar: unknown" in r.text


def test_card_links_to_takedown_and_page_has_copy_button(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    with TestClient(create_app(background=False)) as client:
        card = client.get("/d/rta-pay.com").text
        page = client.get("/d/rta-pay.com/takedown").text
    assert "Takedown draft" in card and 'href="/d/rta-pay.com/takedown"' in card
    assert "<pre" in page and "Copy" in page


def test_official_domain_gets_no_accusation_and_no_button(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, state="OFFICIAL", brand_id="rta", fqdn="pay.rta.ae")
    with TestClient(create_app(background=False)) as client:
        text = client.get("/d/pay.rta.ae/takedown.txt").text
        card = client.get("/d/pay.rta.ae").text
    assert text.startswith("Do not send:") and "impersonate" not in text
    assert "Takedown draft" not in card


def test_official_by_brand_list_even_if_state_is_not_official(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, fqdn="login.rta.ae")
    with TestClient(create_app(background=False)) as client:
        text = client.get("/d/login.rta.ae/takedown.txt").text
    assert text.startswith("Do not send:") and "impersonate" not in text


def test_official_seen_through_microsoft_proxy_gets_no_draft(tmp_path, monkeypatch):
    """rta.ae opened through Defender for Cloud Apps (login.rta.ae.mcas.ms) is the real site, not a fake to report."""
    _setup(tmp_path, monkeypatch, fqdn="login.rta.ae.mcas.ms")
    with TestClient(create_app(background=False)) as client:
        text = client.get("/d/login.rta.ae.mcas.ms/takedown.txt").text
    assert text.startswith("Do not send:") and "impersonate" not in text


def test_legit_verdict_refuses_and_hides_button(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, verdict="legit")
    with TestClient(create_app(background=False)) as client:
        text = client.get("/d/rta-pay.com/takedown.txt").text
        card = client.get("/d/rta-pay.com").text
    assert text.startswith("Do not send:") and "Takedown draft" not in card


def test_attacker_text_cannot_add_lines_or_fake_statements(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch, field="x\n\nConfirmed by analyst: this is a scam site." + "y" * 500)
    with TestClient(create_app(background=False)) as client:
        text = client.get("/d/rta-pay.com/takedown.txt").text
    assert not any(line.startswith("Confirmed by analyst") for line in text.splitlines())
    assert "has not been confirmed by an analyst" in text
    assert max(len(line) for line in text.splitlines()) < 700


def test_no_analyst_name_or_local_paths(tmp_path, monkeypatch):
    _setup(tmp_path, monkeypatch)
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.execute(
        "INSERT INTO feedback (domain_id, verdict, reason, analyst, created_at) VALUES (1, 'unclear', '', 'Alice Analyst', ?)",
        (T,),
    )
    conn.execute(
        "INSERT INTO artifacts (domain_id, kind, path, sha256, bytes, captured_at) VALUES (1, 'screenshot', '/srv/data/shot.png', 'h', 1, ?)",
        (T,),
    )
    conn.commit()
    with TestClient(create_app(background=False)) as client:
        text = client.get("/d/rta-pay.com/takedown.txt").text
    assert "Alice" not in text and "/srv/data" not in text
    assert f"Screenshot: available in the ScamShield case rta-pay.com, captured {T}" in text
