from fastapi.testclient import TestClient

from scamshield.contracts import NormalizedURL, Rejection


def _url():
    return NormalizedURL(
        raw="https://example.com/login",
        url="https://example.com/login",
        scheme="https",
        host="example.com",
        port=443,
        fqdn="example.com",
        registrable="example.com",
        notes=[],
    )


def test_check_redirects_to_card_with_provenanced_live_facts(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    from scamshield.web import routes

    async def check_url(raw):
        return _url()

    monkeypatch.setattr(routes.netsafe, "check_url", check_url)
    from scamshield.app import create_app

    with TestClient(create_app()) as client:
        response = client.post("/check", data={"url": "https://example.com/login"}, follow_redirects=False)
        card = client.get(response.headers["location"])

    assert response.status_code == 303
    assert response.headers["location"] == "/d/example.com?from=paste"
    assert card.status_code == 200
    assert "example.com" in card.text
    assert "Checking…" in card.text
    assert "LIVE" in card.text


def test_bad_url_returns_error_under_input(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    from scamshield.web import routes

    async def check_url(raw):
        return Rejection(
            "PRIVATE_ADDRESS",
            "Blocked: this link points to a private or local network address. Only public internet sites can be checked.",
        )

    monkeypatch.setattr(routes.netsafe, "check_url", check_url)
    from scamshield.app import create_app

    with TestClient(create_app()) as client:
        response = client.post("/check", data={"url": "http://127.0.0.1"})

    assert response.status_code == 200
    assert "Blocked: this link points to a private or local network address." in response.text


def test_check_enqueues_durable_job(tmp_path, monkeypatch):
    import sqlite3

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    from scamshield.web import routes

    async def check_url(raw):
        return _url()

    monkeypatch.setattr(routes.netsafe, "check_url", check_url)
    from scamshield.app import create_app

    with TestClient(create_app(background=False)) as client:  # no worker: it would race the queued assertion
        response = client.post("/check", data={"url": "https://example.com/login"}, follow_redirects=False)

    row = sqlite3.connect(tmp_path / "scamshield.db").execute("SELECT kind, target, status FROM jobs").fetchone()
    assert response.status_code == 303
    assert row == ("check_domain", "example.com", "queued")


def _card_db(tmp_path, monkeypatch, job_status, run_after=None, error=None, extra_jobs=()):
    """A CT domain with an intake lookalike fact and one check_domain job in the given state."""
    import sqlite3

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    from scamshield import db

    path = str(tmp_path / "scamshield.db")
    db.init(path)
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by) VALUES ('rta-pay.com', 'rta-pay.com', 't', 'ct_tiled')"
    )
    conn.execute(
        "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (1, 'lookalike', '{}', 'ct_tiled', 't', 'ok')"
    )
    for n, (status, ra, err) in enumerate([*extra_jobs, (job_status, run_after, error)], 1):
        conn.execute(
            "INSERT INTO jobs (kind, target, status, run_after, error, idem_key) VALUES ('check_domain', 'rta-pay.com', ?, ?, ?, ?)",
            (status, ra, err, f"k{n}"),
        )
    return conn


def _facts_html(conn):
    from scamshield.app import create_app

    conn.commit()
    with TestClient(create_app(background=False)) as client:
        return client.get("/d/rta-pay.com/partials/facts").text


def test_ct_domain_with_lookalike_and_queued_job_keeps_polling(tmp_path, monkeypatch):
    html = _facts_html(_card_db(tmp_path, monkeypatch, "queued"))
    assert 'hx-trigger="every 2s"' in html and "Checking…" in html and "Name contains" in html


def test_retry_time_shown_for_delayed_job(tmp_path, monkeypatch):
    html = _facts_html(_card_db(tmp_path, monkeypatch, "queued", run_after="2999-01-01T12:34:00Z"))
    assert "Retrying at 12:34" in html and "hx-trigger" in html


def test_failed_job_shows_reason_and_stops_polling(tmp_path, monkeypatch):
    html = _facts_html(_card_db(tmp_path, monkeypatch, "failed", error="timeout"))
    assert "no answer (timeout)" in html and "hx-trigger" not in html


def test_two_finished_checks_show_one_fact_set(tmp_path, monkeypatch):
    conn = _card_db(tmp_path, monkeypatch, "done", extra_jobs=[("done", None, None)])
    for job_id in (1, 2):
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status, job_id) VALUES (1, 'dns', '{}', 'dns', 't', 'ok', ?)",
            (job_id,),
        )
    html = _facts_html(conn)
    assert 'id="E3"' in html and 'id="E2"' not in html and html.count('class="ev"') == 2
    assert "hx-trigger" not in html
    assert conn.execute("SELECT COUNT(*) FROM facts").fetchone()[0] == 3  # history stays
