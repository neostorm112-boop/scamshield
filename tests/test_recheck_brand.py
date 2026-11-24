import asyncio
import json
import sqlite3

from scamshield import config, db, intake, worker
from scamshield.contracts import Fact
from scamshield.enrich import lookalike
from scamshield.tools import requeue_rechecks

STAMP = "2026-11-20T08:00:00Z"


def _setup(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def dns_run(fqdn, ctx):
        return [Fact("dns_a", {"records": ["1.2.3.4"]}, "dns", None, STAMP, "ok")]

    async def feed_run(fqdn, ctx):
        return [Fact("in_feed", {"listed": False}, "feed_match", None, STAMP, "ok")]

    async def nothing(fqdn, ctx):
        return []

    for name, run in (
        ("dns", dns_run),
        ("asn", nothing),
        ("rdap", nothing),
        ("certspotter", nothing),
        ("feed_match", feed_run),
    ):
        monkeypatch.setattr(getattr(worker, name), "run", run)
    return config.load()


def _old_row(settings, monkeypatch, fqdn, found_by="ct_tiled"):
    """A domain checked under the OLD brand rules: the intake hit says careem and the check never re-applied the rules."""
    value = lookalike.fact_value(lookalike.match("careem-pay.com", settings.brands, "ct"))
    asyncio.run(intake.submit(fqdn, found_by, [Fact("lookalike", value, "ct_tiled", None, STAMP, "ok")], 10))
    with monkeypatch.context() as m:
        m.setattr(worker, "_recheck_brand", lambda *a: None)
        assert asyncio.run(worker.process_next(settings, None)) is True


def _recheck(settings, fqdn, key="recheck:1"):
    asyncio.run(worker.enqueue("recheck", fqdn, {}, key))
    assert asyncio.run(worker.process_next(settings, None)) is True


def _query(tmp_path, sql, *args):
    return sqlite3.connect(tmp_path / "scamshield.db").execute(sql, args).fetchall()


def _brand(tmp_path, fqdn):
    comp = _query(
        tmp_path,
        "SELECT components_json FROM assessments a JOIN domains d ON d.id = a.domain_id WHERE d.fqdn = ? ORDER BY a.id DESC LIMIT 1",
        fqdn,
    )[0][0]
    return "careem" if json.loads(comp)["B"] > 0 else None  # brand points exist only with a brand hit


def test_recheck_drops_a_brand_the_rules_no_longer_give(tmp_path, monkeypatch):
    settings = _setup(tmp_path, monkeypatch)
    _old_row(settings, monkeypatch, "wellthcareemployer.com")
    assert _brand(tmp_path, "wellthcareemployer.com") == "careem"

    _recheck(settings, "wellthcareemployer.com")
    _recheck(settings, "wellthcareemployer.com", "recheck:2")  # repeated: still one answer

    assert _brand(tmp_path, "wellthcareemployer.com") != "careem"
    assert _query(tmp_path, "SELECT status FROM facts WHERE type = 'lookalike' AND source = 'brand_check'") == [
        ("missing",)
    ]


def test_recheck_keeps_a_real_hit(tmp_path, monkeypatch):
    settings = _setup(tmp_path, monkeypatch)
    _old_row(settings, monkeypatch, "careem-pay.com")

    _recheck(settings, "careem-pay.com")

    assert _brand(tmp_path, "careem-pay.com") == "careem"
    assert _query(tmp_path, "SELECT count(*) FROM facts WHERE source = 'brand_check'") == [(0,)]


def _mark(tmp_path, fqdn, found_by="ct_tiled", verdict=None):
    conn = sqlite3.connect(tmp_path / "scamshield.db")
    conn.execute("UPDATE domains SET found_by = ? WHERE fqdn = ?", (found_by, fqdn))
    if verdict:
        conn.execute(
            "INSERT INTO feedback (domain_id, verdict, reason, analyst, created_at) SELECT id, ?, 'x', 'a', ? FROM domains WHERE fqdn = ?",
            (verdict, STAMP, fqdn),
        )
    conn.commit()


def test_tool_queues_open_rows_only_and_is_idempotent(tmp_path, monkeypatch, capsys):
    settings = _setup(tmp_path, monkeypatch)
    for fqdn in ("careem-pay.com", "careem-login.com", "careem-fix.com"):
        _old_row(settings, monkeypatch, fqdn)
    _mark(tmp_path, "careem-login.com", verdict="legit")
    _mark(tmp_path, "careem-fix.com", found_by="baseline")

    assert requeue_rechecks.main([str(tmp_path), "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "1 domains" in out and "careem-pay.com" in out
    assert _query(tmp_path, "SELECT count(*) FROM jobs WHERE kind = 'recheck'") == [(0,)]

    requeue_rechecks.main([str(tmp_path)])
    requeue_rechecks.main([str(tmp_path)])
    assert _query(tmp_path, "SELECT target FROM jobs WHERE kind = 'recheck'") == [("careem-pay.com",)]
