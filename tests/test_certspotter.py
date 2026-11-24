import asyncio
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from scamshield import config, db, runtime
from scamshield.contracts import Fact

FIXTURE = Path(__file__).parent / "fixtures" / "certspotter_rta.json"


class _Response:
    def __init__(self, payload, status_code=200):
        self._payload, self.status_code = payload, status_code

    def json(self):
        return self._payload


class _Http:
    def __init__(self, payload=None):
        self.calls, self.headers = 0, []
        self._payload = json.loads(FIXTURE.read_text()) if payload is None else payload

    async def get(self, url, **kwargs):
        self.calls += 1
        self.headers.append(kwargs.get("headers"))
        return _Response(self._payload)


def _ctx(tmp_path, http, pool="manual", **cert_cfg):
    db.init(str(tmp_path / "scamshield.db"))
    settings = config.load()
    settings.sources["certspotter"].__dict__.update(cert_cfg)
    return runtime.make_ctx(settings, http, pool)


def test_recorded_answer_becomes_certs_fact_with_source_and_time(tmp_path):
    from scamshield.enrich import certspotter

    facts = asyncio.run(certspotter.run("www.rta.ae", _ctx(tmp_path, _Http())))

    assert len(facts) == 1
    fact = facts[0]
    assert (fact.type, fact.source, fact.status) == ("certs", "certspotter", "ok")
    assert fact.fetched_at and fact.observed_at == "2026-09-02T00:00:00Z"
    assert (
        fact.value["first_issued"] == "2026-09-02T00:00:00Z"
        and fact.value["issuer"] == "DigiCert"
        and fact.value["count"] == 1
    )


def test_no_certificates_is_missing_not_error(tmp_path):
    from scamshield.enrich import certspotter

    facts = asyncio.run(certspotter.run("new.example", _ctx(tmp_path, _Http([]))))

    assert (facts[0].status, facts[0].error) == ("missing", "not_found")


def test_key_from_settings_is_sent_and_absent_key_is_not(tmp_path):
    from scamshield.enrich import certspotter

    ctx = _ctx(tmp_path, _Http())
    asyncio.run(certspotter.run("www.rta.ae", ctx))
    ctx.settings.secrets["CERTSPOTTER_API_KEY"] = "k"
    asyncio.run(certspotter.run("www.rta.ae", ctx))

    assert ctx.http.headers == [None, {"Authorization": "Bearer k"}]


def test_limits_are_40_manual_and_20_auto_per_hour(tmp_path):
    from scamshield.enrich import certspotter

    for pool, limit in (("manual", 40), ("auto", 20)):
        http = _Http()
        ctx = _ctx(tmp_path, http, pool)
        statuses = [asyncio.run(certspotter.run("www.rta.ae", ctx))[0] for _ in range(limit + 1)]

        assert http.calls == limit
        assert (statuses[-1].status, statuses[-1].error) == ("error", "budget")
        assert all(f.status == "ok" for f in statuses[:-1])


def test_disabled_certspotter_is_not_checked_and_other_facts_remain(tmp_path, monkeypatch):
    from scamshield import intake, worker

    monkeypatch.setenv("SCAMSHIELD_DATA_DIR", str(tmp_path))
    db.init(str(tmp_path / "scamshield.db"))

    async def ok(fqdn, ctx):
        return [Fact("ip_asn", {"asn": 1}, "asn", None, "2026-11-19T08:00:00Z", "ok")]

    async def empty(fqdn, ctx):
        return []

    for module in (worker.dns, worker.asn, worker.rdap):
        monkeypatch.setattr(module, "run", ok if module is worker.asn else empty)
    settings = config.load()
    settings.sources["certspotter"].enabled = False
    asyncio.run(intake.submit("example.com", "manual", [], 10))

    assert asyncio.run(worker.process_next(settings, _Http())) is True

    rows = (
        sqlite3.connect(tmp_path / "scamshield.db")
        .execute("SELECT type, status, error FROM facts ORDER BY id")
        .fetchall()
    )
    assert ("certs", "error", "disabled") in rows and ("ip_asn", "ok", None) in rows


def test_card_shows_unknown_registration_date_and_not_checked_certs():
    from scamshield.web.view import _fact_line

    base = {"id": 1, "fetched_at": "2026-11-20T10:00:00Z", "data_mode": "LIVE", "value": {}}
    now = datetime.now(UTC)
    rows = [
        _fact_line(
            {**base, "type": "created_at", "source": "rdap", "status": "missing", "error": "not_found"}, {}, now
        ),
        _fact_line(
            {**base, "id": 2, "type": "certs", "source": "certspotter", "status": "error", "error": "disabled"}, {}, now
        ),
    ]

    assert "Registration date: unknown" in rows[0]["text"]
    assert rows[1]["text"] == "Not checked: certificate search — source disabled" and rows[1]["nc"]
