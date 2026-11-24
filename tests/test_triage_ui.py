import json
import sqlite3

from fastapi.testclient import TestClient


def _seed(path):
    conn = sqlite3.connect(path)
    for fqdn, state, risk, flags, components in [
        (
            "du.ac.bd",
            "NOISE",
            0,
            [],
            {
                "band": "NOISE",
                "reason": "brand token `du` is the registrable label in a restricted zone",
                "breakdown": [
                    "+3 brand in name",
                    "-3 brand token is the registrable label in a restricted zone",
                    "0 age unknown",
                ],
            },
        ),
        (
            "meta-framex-24f.pages.dev",
            "REVIEW",
            0.2,
            ["OTHER_BRAND", "GRAY"],
            {
                "band": "GRAY",
                "reason": "some evidence",
                "breakdown": ["+1 brand on hosting platform (edit distance)", "-1.5 other brand `meta` in name"],
            },
        ),
    ]:
        conn.execute(
            "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score) VALUES (?, ?, '2026-11-20T08:00:00Z', 'feeds', ?, ?)",
            (fqdn, fqdn, state, risk),
        )
        conn.execute(
            "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) "
            "VALUES ((SELECT id FROM domains WHERE fqdn = ?), 'v2-points', ?, 1, ?, ?, ?, '[]', '2026-11-20T08:00:00Z')",
            (fqdn, risk, state, json.dumps(flags), json.dumps(components)),
        )
    conn.commit()


def _client(tmp_path, monkeypatch):
    from scamshield.app import create_app

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    return TestClient(create_app(background=False))


def test_noise_is_hidden_by_default_other_brand_stays_with_label(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        _seed(tmp_path / "scamshield.db")
        page = client.get("/").text

    assert "du.ac.bd" not in page
    assert "meta-framex-24f.pages.dev" in page
    assert "Filtered out (1)" in page


def test_show_filtered_lists_reason_and_return_to_queue_works(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        _seed(tmp_path / "scamshield.db")
        shown = client.get("/?filtered=1").text.replace("<wbr>", "")
        filtered_card = client.get("/d/du.ac.bd").text
        response = client.post("/d/du.ac.bd/restore", follow_redirects=False)
        after = client.get("/").text
        card = client.get("/d/du.ac.bd").text

    assert (
        "du.ac.bd" in shown and "registrable label in a restricted zone" in shown and "Return to queue" in filtered_card
    )
    assert response.status_code == 303
    assert "du.ac.bd" in after.replace("<wbr>", "") and "Filtered out (0)" in after
    verdict = sqlite3.connect(tmp_path / "scamshield.db").execute("SELECT verdict, reason FROM feedback").fetchone()
    assert verdict[0] == "unclear" and "restored" in verdict[1]
    assert "Unclear (analyst)" in card


def test_card_shows_points_breakdown_band_and_flags(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        _seed(tmp_path / "scamshield.db")
        card = client.get("/d/meta-framex-24f.pages.dev").text

    assert "+1 brand on hosting platform (edit distance)" in card and "-1.5 other brand `meta` in name" in card
    assert "Another brand name is in the address too" in card


def test_risk_is_a_plain_number_and_times_are_gst(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        _seed(tmp_path / "scamshield.db")
        conn = sqlite3.connect(tmp_path / "scamshield.db")
        conn.execute(
            "INSERT INTO facts (domain_id, type, value_json, source, fetched_at, status) VALUES (2, 'registrar', '{}', 'rdap', '2026-11-19T21:14:13.708790Z', 'ok')"
        )
        conn.commit()
        feed, card = client.get("/").text, client.get("/d/meta-framex-24f.pages.dev").text

    assert 'aria-label="Risk 20 of 100, Review"' in feed and 'aria-label="Risk 20 of 100"' in card
    assert "%" not in feed.split('id="rows"')[1].split("</ul>")[0] and "20%" not in card
    assert "01:14 GST" in card and "21:14:13" not in card


def test_gst_helper_shows_time_only_for_today():
    from datetime import UTC, datetime

    from scamshield.app import gst

    now = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)
    assert gst("2026-11-20T08:30:00.5Z", now) == "12:30 GST"
    assert gst("2026-11-19T21:14:13Z", now) == "01:14 GST"  # 01:14 on the 20th in GST is still today
    assert gst("2026-11-18T10:00:00Z", now) == "2026-11-18 14:00 GST"
    assert gst("t", now) == "t" and gst(None, now) == ""


def _seed_two(path):
    _seed(path)
    conn = sqlite3.connect(path)
    conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, state, risk_score) VALUES ('second-case.com', 'second-case.com', '2026-11-20T08:00:00Z', 'feeds', 'REVIEW', 0.1)"
    )
    conn.execute(
        "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) "
        "VALUES ((SELECT id FROM domains WHERE fqdn = 'second-case.com'), 'v2-points', 0.1, 1, 'REVIEW', '[]', '{}', '[]', '2026-11-20T08:00:00Z')"
    )
    conn.commit()


def test_saving_a_verdict_opens_the_promised_next_case(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as client:
        _seed_two(tmp_path / "scamshield.db")
        case = client.get("/d/meta-framex-24f.pages.dev").text
        response = client.post(
            "/d/meta-framex-24f.pages.dev/feedback",
            data={"verdict": "legit", "reason": "real shop", "next": "second-case.com"},
            follow_redirects=False,
        )

    assert 'name="next" value="second-case.com"' in case
    assert response.status_code == 303 and response.headers["location"] == "/d/second-case.com"


def test_pasted_link_opens_as_first_row_of_the_queue(tmp_path, monkeypatch):
    from scamshield.contracts import NormalizedURL
    from scamshield.web import routes

    async def check_url(raw):
        return NormalizedURL(
            raw=raw,
            url=raw,
            scheme="https",
            host="pasted-check.example.com",
            port=443,
            fqdn="pasted-check.example.com",
            registrable="example.com",
            notes=[],
        )

    monkeypatch.setattr(routes.netsafe, "check_url", check_url)
    with _client(tmp_path, monkeypatch) as client:
        _seed_two(tmp_path / "scamshield.db")
        response = client.post("/check", data={"url": "https://pasted-check.example.com/pay"}, follow_redirects=False)
        page = client.get(response.headers["location"]).text.replace("<wbr>", "")

    assert response.status_code == 303 and response.headers["location"] == "/d/pasted-check.example.com?from=paste"
    first_row = page[page.index('<ul class="q-list"') :].split("</li>")[0]
    assert "pasted-check.example.com" in first_row and "pasted" in first_row and 'aria-current="true"' in first_row
