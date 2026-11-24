import asyncio
import io

from scamshield import worker
from scamshield.contracts import Fact
from scamshield.tools import check_set

STAMP = "2026-11-19T08:00:00Z"
OLD_AND_FAKE = "aramax-old.com"  # edit-distance brand-fit only, domain from 2010: the formula calls it old and established -> NOISE


def _csv(tmp_path, *rows):
    path = tmp_path / "set.csv"
    path.write_text("domain,expected,synthetic,proof\n" + "".join(f"{r}\n" for r in rows), encoding="utf-8")
    return str(path)


def _stub(monkeypatch):
    async def dns_run(fqdn, ctx):
        return [Fact("dns_a", {"records": ["1.2.3.4"]}, "dns", None, STAMP, "ok")]

    async def asn_run(fqdn, ctx):
        return [Fact("ip_asn", {"asn": 1}, "asn", None, STAMP, "ok")]

    async def rdap_run(fqdn, ctx):
        return [
            Fact(
                "created_at",
                {"date": "2010-01-01T00:00:00Z" if fqdn == OLD_AND_FAKE else "2026-11-15T00:00:00Z"},
                "rdap",
                None,
                STAMP,
                "ok",
            )
        ]

    async def certs_run(fqdn, ctx):
        return [
            Fact(
                "certs",
                {"first_issued": "2012-01-01T00:00:00Z" if fqdn == OLD_AND_FAKE else "2026-11-16T00:00:00Z"},
                "certspotter",
                None,
                STAMP,
                "ok",
            )
        ]

    async def feed_run(fqdn, ctx):
        return [Fact("in_feed", {"listed": False}, "feed_match", None, STAMP, "ok")]

    for name, run in (
        ("dns", dns_run),
        ("asn", asn_run),
        ("rdap", rdap_run),
        ("certspotter", certs_run),
        ("feed_match", feed_run),
    ):
        monkeypatch.setattr(getattr(worker, name), "run", run)


def test_check_set_prints_table_and_exits_zero_when_official_and_fakes_are_fine(tmp_path, monkeypatch):
    _stub(monkeypatch)
    out = io.StringIO()
    path = _csv(tmp_path, "rta.ae,OFFICIAL,0,brands", "aramex-parcel-hold-7731.com,FAKE,1,SYNTHETIC")

    code = asyncio.run(check_set.run(path, out))

    text = out.getvalue()
    assert code == 0 and "2 domains, 0 failed" in text
    assert (
        "rta.ae" in text
        and "OFFICIAL" in text
        and "aramex-parcel-hold-7731.com [synthetic]" in text
        and "points" in text
    )


def test_check_set_fails_when_a_fake_is_in_noise_or_an_official_is_not_official(tmp_path, monkeypatch):
    _stub(monkeypatch)
    out = io.StringIO()

    code = asyncio.run(
        check_set.run(_csv(tmp_path, f"{OLD_AND_FAKE},FAKE,0,x", "aramex-login-help.com,OFFICIAL,0,wrong label"), out)
    )

    text = out.getvalue()
    assert code == 1 and "NOISE" in text and "2 domains, 2 failed" in text
