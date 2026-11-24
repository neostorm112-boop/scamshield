import asyncio
import sqlite3
import subprocess
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from scamshield import app as app_module
from scamshield import config, db, live, worker

T0 = datetime(2026, 11, 20, 19, 0, tzinfo=UTC)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SCAMSHIELD_LIVE", "1")
    live._last.clear()
    db.init(str(tmp_path / "scamshield.db"))
    return db._conn()


def _domain(conn, fqdn, found_by, mode="LIVE"):
    conn.execute(
        "INSERT INTO domains (fqdn, registrable, first_seen_at, found_by, data_mode) VALUES (?, ?, ?, ?, ?)",
        (fqdn, fqdn, "2026-11-20T18:00:00Z", found_by, mode),
    )
    conn.commit()


def test_old_database_gets_jobs_created_at_and_new_jobs_have_it(tmp_path):
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.execute(
        "CREATE TABLE jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, class TEXT NOT NULL DEFAULT 'light', target TEXT NOT NULL, "
        "payload_json TEXT NOT NULL DEFAULT '{}', priority INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued', "
        "attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3, run_after TEXT, started_at TEXT, finished_at TEXT, error TEXT, idem_key TEXT NOT NULL UNIQUE)"
    )
    old.commit()
    old.close()
    db.init(path)
    worker.enqueue_in(db._conn(), "check_domain", "a.com", {}, "k1")

    assert db._conn().execute("SELECT created_at FROM jobs").fetchone()[0].endswith("Z")


def test_parse_ts_reads_sqlite_and_iso_formats():
    assert live.parse_ts("2026-11-20 19:00:00") == T0
    assert live.parse_ts("2026-11-20T19:00:00Z") == T0
    assert live.parse_ts("junk") is None and live.parse_ts(None) is None


def test_sleep_gap_is_recorded_as_a_pause(conn):
    live.beat(conn, "worker", now=T0)
    live.beat(conn, "worker", now=T0 + timedelta(seconds=60))
    live.beat(conn, "worker", now=T0 + timedelta(seconds=60 + 900))

    pauses = conn.execute("SELECT at, lag_s FROM heartbeats WHERE loop = 'pause'").fetchall()
    assert [(p["at"], p["lag_s"]) for p in pauses] == [("2026-11-20T19:16:00Z", 900)]


def test_counters_skip_baseline_and_demo(conn):
    live.beat(conn, "boot", now=T0)
    live.beat(conn, "ct:willow", entries=1000, tree_size=5000, now=T0)
    live.beat(conn, "ct:willow", entries=500, tree_size=5500, now=T0)
    for fqdn, found_by, mode in [
        ("a.com", "ct_tiled", "LIVE"),
        ("b.com", "baseline", "LIVE"),
        ("c.com", "ct_tiled", "DEMO"),
        ("d.com", "feeds", "LIVE"),
        ("e.com", "manual", "LIVE"),
    ]:
        _domain(conn, fqdn, found_by, mode)
        conn.execute(
            "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) "
            "SELECT id, 'v', 0, 1, 'REVIEW', '[]', ?, '[]', '2026-11-20T18:01:00Z' FROM domains WHERE fqdn = ?",
            ('{"band": "NOISE"}' if fqdn == "e.com" else '{"band": "GRAY"}', fqdn),
        )  # e.com: assessed as noise, not a find
    conn.commit()

    counters = live.health(conn, now=T0)["counters"]

    assert counters == {"certs_checked": 1500, "finds": 1, "list_echoes": 1}


def test_banner_green_amber_red(conn):
    live.beat(conn, "boot", now=T0)
    live.beat(conn, "ct:willow", now=T0)
    live.beat(conn, "ct:sycamore", now=T0)
    live.beat(conn, "worker", now=T0)
    assert live.health(conn, now=T0 + timedelta(seconds=30))["banner"]["state"] == "green"

    live.beat(conn, "ct:sycamore", ok=False, error="http_500", now=T0 + timedelta(seconds=100))
    live.beat(conn, "ct:willow", now=T0 + timedelta(seconds=100))
    amber = live.health(conn, now=T0 + timedelta(seconds=120))["banner"]
    assert amber["state"] == "amber" and "1 source degraded" in amber["text"]

    red = live.health(conn, now=T0 + timedelta(seconds=100 + 700))["banner"]
    assert red["state"] == "red" and red["text"].startswith("OFFLINE") and "showing data found before" in red["text"]


def test_ct_log_not_polled_since_restart_is_retired_not_degraded(conn):
    live.beat(conn, "boot", now=T0)
    live.beat(conn, "ct:skylight", now=T0)  # old name, before the per-shard names
    live.beat(conn, "boot", now=T0 + timedelta(hours=8))
    later = T0 + timedelta(hours=8, minutes=10)
    live.beat(conn, "ct:skylight/tuscolo2027h1", now=later)
    health = live.health(conn, now=later)
    assert "ct:skylight" not in health["loops"] and health["retired_loops"] == ["ct:skylight"]
    assert health["banner"]["state"] == "green"
    # right after a restart a log that has not answered yet is still judged as before (not hidden)
    live.beat(conn, "boot", now=later)
    soon = live.health(conn, now=later + timedelta(seconds=60))
    assert "ct:skylight/tuscolo2027h1" in soon["loops"]


def test_banner_is_empty_outside_live_mode(conn, monkeypatch):
    monkeypatch.delenv("SCAMSHIELD_LIVE")
    assert live.health(conn, now=T0)["banner"] is None and live.health(conn, now=T0)["mode"] == "DEV"


def test_healthz_reports_worker_heartbeat_and_queue(conn):
    live.beat(conn, "worker")
    worker.enqueue_in(conn, "check_domain", "a.com", {}, "k1")
    conn.commit()
    with TestClient(app_module.create_app(background=False)) as client:
        body = client.get("/healthz").json()

    assert body["mode"] == "LIVE" and body["loops"]["worker"]["status"] == "ok"
    assert body["queue"]["queued"] == 1 and body["worker_age_s"] < 60


def test_feed_rows_mark_new_finds_and_say_how_found(conn):
    live.beat(conn, "boot")
    _domain(conn, "old-rta.com", "ct_tiled")
    _domain(conn, "new-rta.com", "feeds")
    conn.execute("UPDATE domains SET first_seen_at = '2019-12-31T20:00:00Z' WHERE fqdn = 'old-rta.com'")
    worker.enqueue_in(conn, "check_domain", "old-rta.com", {}, "k1")
    conn.execute("UPDATE jobs SET created_at = '2020-01-01T00:00:00Z'")
    worker.enqueue_in(conn, "check_domain", "new-rta.com", {}, "k2")
    conn.commit()
    with TestClient(app_module.create_app(background=False)) as client:
        body = client.get("/partials/feed-rows", params={"since": "2021-01-01T00:00:00Z"}).text
        page = client.get("/").text
        script = client.get("/static/app.js").text

    assert body.count('class="new"') == 1
    body = body.replace("<wbr>", "")
    new_row = body[body.rindex("<li", 0, body.index("new-rta.com")) : body.index("</li>", body.index("new-rta.com"))]
    assert 'class="new"' in new_row
    old_row = body[body.index("old-rta.com") : body.index("</li>", body.index("old-rta.com"))]
    assert 'class="new"' not in old_row
    assert (
        "found via phishing list" in client.get("/d/new-rta.com").text
        and "found via cert log" in client.get("/d/old-rta.com").text
    )
    assert 'hx-get="/partials/banner"' in page and "Connection to ScamShield lost" in script


def test_banner_partial_shows_pulse_line(conn):
    live.beat(conn, "boot")
    live.beat(conn, "ct:willow", entries=2000, tree_size=9000)
    with TestClient(app_module.create_app(background=False)) as client:
        text = client.get("/partials/banner").text

    assert "LIVE" in text and "2 000 certificates checked" in text.replace(" ", " ").replace("\xa0", " ")


def test_feeds_are_not_downloaded_on_restart_inside_refresh_window(conn):
    settings = config.load()
    fresh = (datetime.now(UTC) - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    conn.execute(
        "INSERT INTO feed_meta (key, value) VALUES ('feed:openphish', ?)", (f'{{"fetched_at": "{fresh}", "count": 1}}',)
    )
    conn.commit()

    class NoHttp:
        def stream(self, *args, **kwargs):
            raise AssertionError("must not download")

    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(asyncio.wait_for(app_module.monitor_feeds(settings, NoHttp()), 0.5))
    assert conn.execute("SELECT ok FROM heartbeats WHERE loop = 'feeds'").fetchone()[0] == 1


@pytest.mark.parametrize(
    "args",
    [
        ["start", "x", "8765"],
        ["start", "x", "8766"],
        ["start", "day1", "8799"],
        ["start", "../x", "8799"],
        ["start", "x", "abc"],
    ],
)
def test_live_sh_refuses_protected_names_and_ports(args):
    done = subprocess.run(["scripts/live.sh", *args], check=False, capture_output=True, text=True, timeout=20)
    assert done.returncode != 0 and "refus" in (done.stdout + done.stderr).lower()


def test_health_reports_ct_age_apart_from_worker_age(conn):
    now = datetime(2026, 11, 21, 14, 30, tzinfo=UTC)
    live.beat(conn, "worker", now=now - timedelta(seconds=10))
    live.beat(conn, "ct:sycamore", now=now - timedelta(seconds=400))
    live.beat(conn, "ct:willow", now=now - timedelta(seconds=30))

    health = live.health(conn, now)

    assert (health["worker_age_s"], health["ct_age_s"]) == (10, 30)


def test_ct_loop_names_each_shard():
    """Two shards of one operator are two trees; one shared name broke M1 coverage."""
    a = live.ct_loop("https://mon.willow.ct.letsencrypt.org/2026h2")
    b = live.ct_loop("https://mon.willow.ct.letsencrypt.org/2027h1")
    assert a == "ct:willow/2026h2" and b == "ct:willow/2027h1"
    assert live.ct_loop("https://ct.example.org") == "ct:example"


def test_ct_beat_stores_the_cursor_so_a_killed_cycle_is_not_lost(conn):
    live.ct_beat(
        conn,
        "https://ct.example/willow/2026h2",
        "100",
        {"status": "ok", "cursor": "250", "size": 300, "records": 0, "last_ts": None},
        now=T0,
    )

    row = conn.execute("SELECT cursor, entries FROM heartbeats WHERE loop LIKE 'ct:%'").fetchone()

    assert row["cursor"] == 250 and row["entries"] == 150


def test_ct_loop_names_geomys_shards_apart():
    assert live.ct_loop("https://tuscolo2026h2.skylight.geomys.org") == "ct:skylight/tuscolo2026h2"
    assert live.ct_loop("https://tuscolo2026h2.skylight.geomys.org") != live.ct_loop(
        "https://trastevere2026h2.skylight.geomys.org"
    )
