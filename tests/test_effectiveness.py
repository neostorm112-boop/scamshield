import csv
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from scamshield import db
from scamshield.tools import effectiveness as eff

T0 = datetime(2026, 11, 20, 19, 0, tzinfo=UTC)


def iso(seconds):
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


@pytest.fixture
def path(tmp_path):
    p = str(tmp_path / "scamshield.db")
    db.init(p)
    return p


def _add(path, fn):
    c = sqlite3.connect(path)
    fn(c)
    c.commit()
    c.close()


def _domain(c, fqdn, found_by, seen, mode="LIVE", brand="rta"):
    c.execute(
        "INSERT INTO domains (fqdn, registrable, brand_id, first_seen_at, found_by, data_mode) VALUES (?, ?, ?, ?, ?, ?)",
        (fqdn, fqdn, brand, seen, found_by, mode),
    )


def _band(c, fqdn, band):
    c.execute(
        "INSERT INTO assessments (domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at) "
        "SELECT id, 'v', 0, 1, 'REVIEW', '[]', ?, '[]', ? FROM domains WHERE fqdn = ?",
        (f'{{"band": "{band}"}}', iso(1), fqdn),
    )


def _job(c, fqdn, created, started=None, finished=None):
    c.execute(
        "INSERT INTO jobs (kind, target, status, created_at, started_at, finished_at, idem_key) VALUES ('check_domain', ?, 'done', ?, ?, ?, ?)",
        (fqdn, created, started or created, finished or created, f"k-{fqdn}"),
    )


def _beats(c, loop, times, **kw):
    for t in times:
        c.execute(
            "INSERT INTO heartbeats (at, loop, ok, entries, tree_size, skipped, lag_s) VALUES (?, ?, 1, ?, ?, 0, 0)",
            (iso(t), loop, kw.get("entries", 0), kw.get("tree", 0)),
        )


def test_ct_ingest_latency_is_our_ingest_minus_cert_time(path):
    _add(
        path,
        lambda c: (_domain(c, "ct-rta.com", "ct_tiled", iso(0)), _job(c, "ct-rta.com", iso(90), iso(95), iso(100))),
    )

    m = eff.compute([path])

    assert m["M4"]["ct_ingest"]["p95"] == 90 and m["M4"]["queue"]["p95"] == 5 and m["M4"]["check"]["p95"] == 5


def test_baseline_demo_and_feeds_are_not_finds_or_precision(path):
    def fill(c):
        _domain(c, "b.com", "baseline", iso(0))
        _domain(c, "demo.com", "ct_tiled", iso(0), mode="DEMO")
        _domain(c, "echo.com", "feeds", iso(0))
        _domain(c, "ct.com", "ct_tiled", iso(0))
        _band(c, "ct.com", "GRAY")
        for fq in ("echo.com", "ct.com"):
            c.execute(
                "INSERT INTO feedback (domain_id, verdict, reason, created_at) SELECT id, 'scam', 'GSB unsafe', ? FROM domains WHERE fqdn = ?",
                (iso(10), fq),
            )

    _add(path, fill)

    m = eff.compute([path])

    assert m["M5"]["discovery"] == {"ct_tiled": 1} and m["M5"]["echoes"] == {"feeds": 1}
    assert (m["M6"]["tp"], m["M6"]["labelled"]) == (1, 1) and m["M6f"]["total"] == 1


def test_finds_count_only_gray_and_further_split_by_source(path):
    def fill(c):
        for fq, src, band in [
            ("g.com", "web search", "GRAY"),
            ("f.com", "ct_tiled", "FURTHER"),
            ("n.com", "web search", "NOISE"),
            ("o.com", "web search", "OFFICIAL"),
            ("l.com", "ct_tiled", "GRAY_LOW"),
            ("u.com", "web search", None),
        ]:
            _domain(c, fq, src, iso(0))
            if band:
                _band(c, fq, band)

    _add(path, fill)

    assert eff.compute([path])["M5"]["discovery"] == {"web search": 1, "ct_tiled": 1}


def test_unplanned_gap_is_gap_minus_planned_and_pauses(path, tmp_path):
    _add(path, lambda c: (_beats(c, "ct:willow", [0, 60, 1260, 1320]), _beats(c, "worker", [0, 1320])))
    (tmp_path / "planned_gaps").write_text(f"{iso(100)},{iso(700)},upgrade\n")

    m = eff.compute([path], run_dir=str(tmp_path))

    gap = m["M2"]["loops"]["ct:willow"]["gaps"][0]
    assert gap["seconds"] == 1200 and gap["unplanned_s"] == 600 and gap["excused_s"] == 600


def test_pause_rows_and_restarts_excuse_gaps_and_are_listed(path, tmp_path):
    def fill(c):
        _beats(c, "ct:willow", [0, 60, 1260])
        c.execute(
            "INSERT INTO heartbeats (at, loop, ok, lag_s, error) VALUES (?, 'pause', 0, 1000, 'asleep')", (iso(1260),)
        )

    _add(path, fill)

    m = eff.compute([path])

    assert m["M2"]["loops"]["ct:willow"]["gaps"][0]["unplanned_s"] == 200 and len(m["pauses"]) == 1


def test_old_schema_db_gives_na_not_a_crash(tmp_path):
    p = str(tmp_path / "old.db")
    c = sqlite3.connect(p)
    c.execute(
        "CREATE TABLE domains (id INTEGER PRIMARY KEY, fqdn TEXT, found_by TEXT, first_seen_at TEXT, data_mode TEXT, brand_id TEXT)"
    )
    c.commit()
    c.close()

    m = eff.compute([p])
    text = eff.render(m, "old")

    assert m["M1"] is None and m["M4"] is None and "n/a (run predates heartbeats)" in text


def test_coverage_uptime_lag_and_verdicts(path):
    def fill(c):
        _beats(c, "boot", [0])
        for i in range(0, 4000, 10):
            c.execute(
                "INSERT INTO heartbeats (at, loop, ok, entries, tree_size, skipped, lag_s) VALUES (?, 'ct:willow', 1, 10, ?, 0, 5)",
                (iso(i), 1000 + 10 * i // 10 * 1),
            )

    _add(path, fill)

    m = eff.compute([path])

    assert m["M1"]["ct:willow"]["coverage_pct"] >= 99 and m["M3"]["p95"] == 5
    assert m["verdicts"]["M1"] == "GOOD" and m["verdicts"]["M3"] == "GOOD"


def test_integrity_counts_synthetic_and_finds_before_run_start(path):
    def fill(c):
        _beats(c, "boot", [100])
        _domain(c, "syn.com", "ct_tiled", iso(0), mode="SYNTHETIC")
        _domain(c, "early.com", "ct_tiled", iso(0))
        _job(c, "early.com", iso(50))

    _add(path, fill)

    m = eff.compute([path])

    assert m["M11"]["synthetic"] == 1 and m["M11"]["before_start"] == 1 and m["verdicts"]["M11"] == "BAD"


def test_blind_label_export_hides_score_and_state_and_mixes_decoys(path, tmp_path):
    def fill(c):
        for i in range(10):
            _domain(c, f"ct{i}-rta.com", "ct_tiled", iso(i))
            _band(c, f"ct{i}-rta.com", "FURTHER")
        c.execute("UPDATE domains SET state = 'REVIEW_HIGH', risk_score = 0.9")

    _add(path, fill)
    out = tmp_path / "to_label.csv"

    eff.export_labels([path], str(out))

    rows = list(csv.DictReader(out.open()))
    assert set(rows[0]) == {"fqdn", "brand", "source"} and len(rows) == 12
    key = list(csv.DictReader((tmp_path / "to_label_key.csv").open()))
    assert sum(r["decoy"] == "1" for r in key) == 2


def test_database_is_opened_read_only(path):
    c = eff._open(path)
    with pytest.raises(sqlite3.OperationalError):
        c.execute("CREATE TABLE x (a)")


def test_report_text_has_separate_tables_and_verdict_line(path):
    _add(path, lambda c: _domain(c, "echo.com", "feeds", iso(0)))

    text = eff.render(eff.compute([path]), "r1")

    assert "## Our finds (discovery)" in text and "## List echoes" in text and "Verdict:" in text


def _cursor_beat(c, t, cursor, entries, tree, cur=True):
    c.execute(
        "INSERT INTO heartbeats (at, loop, ok, entries, tree_size, skipped, lag_s"
        + (", cursor" if cur else "")
        + ") VALUES (?, 'ct:willow', 1, ?, ?, 0, 0"
        + (", ?)" if cur else ")"),
        (iso(t), entries, tree, *((cursor,) if cur else ())),
    )


def test_m1_counts_tiles_of_a_cycle_killed_before_its_heartbeat(path):
    def fill(c):
        _cursor_beat(c, 0, 1000, 100, 1100)
        _cursor_beat(c, 600, 2000, 300, 2100)  # 700 entries of the killed cycle have no beat of their own

    _add(path, fill)

    assert eff.compute([path])["M1"]["ct:willow"]["coverage_pct"] == 100


def test_m1_old_rows_without_cursor_keep_the_entries_sum(path):
    def fill(c):
        _cursor_beat(c, 0, None, 100, 1100, cur=False)
        _cursor_beat(c, 600, None, 300, 2100, cur=False)

    _add(path, fill)

    m1 = eff.compute([path])["M1"]["ct:willow"]

    assert m1["read"] == 400 and m1["coverage_pct"] == 40.0


def test_m4_ct_ingest_excludes_waits_across_a_machine_pause(path):
    def fill(c):
        _domain(c, "slept.com", "ct_tiled", iso(0))
        _job(c, "slept.com", iso(2000))
        _domain(c, "fast.com", "ct_tiled", iso(3000))
        _job(c, "fast.com", iso(3060))
        c.execute(
            "INSERT INTO heartbeats (at, loop, ok, lag_s, error) VALUES (?, 'pause', 0, 1500, 'asleep')", (iso(1900),)
        )

    _add(path, fill)

    m = eff.compute([path])
    text = eff.render(m, "t")

    assert (
        m["M4"]["ct_ingest"]["n"] == 1 and m["M4"]["ct_ingest"]["p95"] == 60 and m["M4"]["ct_ingest"]["excluded"] == 1
    )
    assert "excluded 1 (machine pause)" in text
