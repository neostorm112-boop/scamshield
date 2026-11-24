from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

from scamshield.config import CONFIG_DIR, load_brands
from scamshield.contracts import Edge, FactRow, Verdict
from scamshield.enrich.lookalike import is_regional_official, match
from scamshield.scoring import assess

NOW = datetime.fromisoformat("2026-11-20T10:00:00+00:00")
BRANDS = load_brands(Path("config/brands.yaml"))
SCORING = yaml.safe_load((CONFIG_DIR / "scoring.yaml").read_text(encoding="utf-8"))
EXAMPLES = yaml.safe_load(Path("tests/fixtures/triage_examples.yaml").read_text(encoding="utf-8"))


def _facts(
    lookalike=None, feeds=(), resolves=False, age_days=None, cert_age_days=None, ok_checks=True
) -> list[FactRow]:
    """Every check answered (missing counts as done) unless ok_checks=False, so coverage is not what a test is about."""
    stamp = NOW.isoformat().replace("+00:00", "Z")
    rows = []

    def add(type_, value, status="ok", source="test"):
        rows.append(FactRow(type_, value, source, None, stamp, status, id=len(rows) + 1))

    if lookalike:
        add("lookalike", lookalike, source="lookalike")
    if ok_checks:
        add("dns_a", {"records": ["1.2.3.4"]} if resolves else {}, "ok" if resolves else "missing")
        add("ip_asn", {}, "missing")
        add("in_feed", {"listed": True, "feeds": list(feeds)} if feeds else {"listed": False})
        add(
            "created_at",
            {"date": (NOW - timedelta(days=age_days)).isoformat()} if age_days is not None else {},
            "ok" if age_days is not None else "missing",
        )
        add(
            "certs",
            {"first_issued": (NOW - timedelta(days=cert_age_days)).isoformat()} if cert_age_days is not None else {},
            "ok" if cert_age_days is not None else "missing",
        )
    return rows


def _assess(fqdn, facts, **kwargs):
    return assess(
        fqdn,
        facts,
        kwargs.get("edges", []),
        kwargs.get("verdict"),
        kwargs.get("neighbours", []),
        BRANDS,
        SCORING,
        kwargs.get("url_paths", ()),
    )


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda e: f"{e['n']}-{e['fqdn']}")
def test_worked_example(example):
    if example.get("sieve_drops"):
        assert match(example["fqdn"], BRANDS, "ct") is None
        assert match(example["fqdn"], BRANDS, "feed") is None
        return
    facts = _facts(
        example["lookalike"],
        example.get("feeds", ()),
        example.get("resolves", False),
        example.get("age_days"),
        example.get("cert_age_days"),
    )
    result = _assess(example["fqdn"], facts)
    expect = example["expect"]

    assert (result.components["B"], result.components["R"]) == (expect["B"], expect["R"])
    assert result.components["band"] == expect["band"]
    assert result.state == expect["state"]
    assert set(expect.get("flags", [])) <= set(result.flags)
    if "reason" in expect:
        assert expect["reason"] in result.components["reason"]


def test_official_domain_is_never_high_risk():
    result = _assess("rta.ae", [])

    assert result.state == "OFFICIAL"
    assert result.risk_score == 0
    assert "OFFICIAL_DOMAIN" in result.flags


def test_every_official_domain_of_every_brand_is_official():
    domains = [d for brand in BRANDS for d in brand.official_domains]

    assert len(domains) >= 10
    assert {_assess(domain, _facts()).state for domain in domains} == {"OFFICIAL"}
    assert {_assess(f"login.{domain}", _facts()).state for domain in domains} == {"OFFICIAL"}


def test_unknown_only_domain_is_gray_low_or_need_more_data_never_noise():
    weak = {
        "brand": "aramex",
        "keyword": "aramex",
        "label": "aramax",
        "method": "edit-distance",
        "position": "registrable",
        "restricted_zone": False,
        "context": "none",
        "context_words": [],
    }
    cases = [_facts(weak), _facts(weak, ok_checks=False), _facts(), _facts(ok_checks=False)]

    states = {_assess("aramax-x.com", facts).components["band"] for facts in cases}

    assert states <= {"GRAY_LOW", "NEED_MORE_DATA"}
    assert "NEED_MORE_DATA" in states and "GRAY_LOW" in states


def test_unknown_age_is_zero_points_and_shown_in_breakdown():
    result = _assess(
        "salik-recharge.top",
        _facts(
            {
                "brand": "salik",
                "keyword": "salik",
                "method": "token",
                "position": "registrable",
                "context_words": ["recharge"],
            },
            feeds=["openphish"],
        ),
    )

    assert result.components["breakdown"] == [
        "+3 brand in name",
        "+1 context: recharge",
        "+3 OpenPhish",
        "0 age unknown",
        "0 certificate unknown",
    ]


def test_regional_official_site_is_capped_at_gray_but_a_fake_is_not():
    look = {
        "brand": "adcb",
        "keyword": "adcb",
        "label": "adcb",
        "method": "token",
        "position": "registrable",
        "restricted_zone": False,
        "context_words": ["login"],
    }
    kwargs = {"resolves": True, "age_days": 3, "feeds": ("openphish",)}
    regional = _assess("online.adcb.com.eg", _facts(look, **kwargs))
    fake = _assess("adcb-login.com.eg", _facts(look, **kwargs))

    assert regional.components["band"] == "GRAY" and fake.components["band"] == "FURTHER"
    assert (
        _assess(
            "login.emiratesnbd.bank.in",
            _facts({**look, "brand": "emiratesnbd", "keyword": "emiratesnbd", "label": "emiratesnbd"}, **kwargs),
        ).components["band"]
        == "GRAY"
    )
    for cheap in ("adcb.top", "adcb.xyz", "rta.top"):
        assert not is_regional_official(cheap, BRANDS), cheap


REGIONAL_REASON = (
    "Same name as the official site on a country domain — likely the brand's own regional site; an analyst confirms"
)


@pytest.mark.parametrize(
    "host,brand,label",
    [
        ("www.aramex.com.au", "aramex", "aramex"),
        ("online.adcb.com.eg", "adcb", "adcb"),
        ("login.emiratesnbd.bank.in", "emiratesnbd", "emiratesnbd"),
        ("www.emiratesnbd.com.sa", "emiratesnbd", "emiratesnbd"),
        ("login.emiratesnbd.com.eg", "emiratesnbd", "emiratesnbd"),
    ],
)
def test_same_name_on_country_domain_is_gray_low(host, brand, label):
    look = {
        "brand": brand,
        "keyword": label,
        "label": label,
        "method": "token",
        "position": "registrable",
        "restricted_zone": False,
        "context_words": [],
    }
    result = _assess(host, _facts(look, resolves=True, age_days=3))

    assert result.components["band"] == "GRAY_LOW" and result.components["reason"] == REGIONAL_REASON


@pytest.mark.parametrize(
    "host,brand",
    [
        ("aramex-ae.top", "aramex"),
        ("emiratesnbd.online", "emiratesnbd"),
        ("adcb.com.eg.secure-login.top", "adcb"),
        ("aramex.com.au.verify-parcel.xyz", "aramex"),
    ],
)
def test_lookalikes_on_cheap_domains_stay_suspects(host, brand):
    look = {
        "brand": brand,
        "keyword": brand,
        "label": brand,
        "method": "token",
        "position": "subdomain",
        "restricted_zone": False,
        "context_words": [],
    }
    result = _assess(host, _facts(look, resolves=True, age_days=3))

    assert result.components["reason"] != REGIONAL_REASON and not is_regional_official(host, BRANDS)


def test_regional_host_in_phishing_feed_keeps_its_band():
    look = {
        "brand": "aramex",
        "keyword": "aramex",
        "label": "aramex",
        "method": "token",
        "position": "registrable",
        "restricted_zone": False,
        "context_words": [],
    }
    result = _assess("www.aramex.com.au", _facts(look, resolves=True, age_days=3, feeds=("openphish",)))

    assert result.components["band"] in ("GRAY", "FURTHER")


def test_gov_ae_host_is_not_boosted_and_is_noise_when_weak():
    look = {
        "brand": "rta",
        "keyword": "rta",
        "label": "rta",
        "method": "token",
        "position": "subdomain",
        "restricted_zone": False,
        "context_words": [],
    }
    result = _assess("rta.itc.gov.ae", _facts(look))

    assert "GOV_AE" in result.flags and result.state == "NOISE"
    assert _assess("darb.itc.gov.ae-pay.com", _facts(look)).state != "NOISE"


def test_guard_keeps_restricted_zone_name_out_of_noise_when_openphish_path_names_the_brand():
    look = {
        "brand": "aramex",
        "keyword": "aramex",
        "label": "aramex",
        "method": "token",
        "position": "registrable",
        "restricted_zone": True,
        "context_words": [],
    }

    assert _assess("aramex.ac.bd", _facts(look)).state == "NOISE"
    guarded = _assess("aramex.ac.bd", _facts(look), url_paths=["/aramex/track"])
    assert guarded.state != "NOISE" and "GUARD:G3" in guarded.flags


def test_short_token_in_feed_path_does_not_trigger_guard_g3():
    look = {
        "brand": "du",
        "keyword": "du",
        "label": "du",
        "method": "token",
        "position": "registrable",
        "restricted_zone": True,
        "context_words": [],
    }

    assert _assess("du.ac.bd", _facts(look), url_paths=["/du/login"]).state == "NOISE"


def test_confirmed_neighbour_edge_is_guard_g2():
    look = {
        "brand": "aramex",
        "keyword": "aramex",
        "label": "aramex",
        "method": "token",
        "position": "registrable",
        "restricted_zone": True,
        "context_words": [],
    }
    edge = Edge("aramex.ac.bd", "scam.example", "ip", "1.2.3.4", 0.9, 0.6, "same ip", [])

    result = _assess("aramex.ac.bd", _facts(look), edges=[edge], neighbours=["scam.example"])

    assert result.state != "NOISE" and "GUARD:G2" in result.flags


def test_analyst_verdict_wins_and_unclear_keeps_domain_out_of_noise():
    look = {
        "brand": "du",
        "keyword": "du",
        "label": "du",
        "method": "token",
        "position": "registrable",
        "restricted_zone": True,
        "context_words": [],
    }

    assert _assess("du.ac.bd", _facts(look), verdict=Verdict("scam", "x", None, "t")).state == "ANALYST_SCAM"
    assert _assess("du.ac.bd", _facts(look), verdict=Verdict("legit", "x", None, "t")).state == "ANALYST_LEGIT"
    assert _assess("du.ac.bd", _facts(look), verdict=Verdict("unclear", "restored", None, "t")).state == "REVIEW"


def test_4b_feed_hits_have_no_uae_fake_in_noise():
    from scamshield.enrich.lookalike import fact_value

    rows = yaml.safe_load(Path("tests/fixtures/triage_4b_hits.yaml").read_text(encoding="utf-8"))
    results = {}
    for row in rows:
        hit = match(row["fqdn"], BRANDS, "feed", row["url_path"])
        if (
            hit is None
        ):  # no longer a brand candidate at all (dewa needs context: mail.dewa.kitchen) — allowed only for noise rows
            assert row["may_be_noise"], row["fqdn"]
            continue
        facts = _facts(fact_value(hit), row["feeds"], resolves=True)
        results[row["fqdn"]] = _assess(row["fqdn"], facts, url_paths=[row["url_path"]] if row["url_path"] else [])

    assert len(rows) >= 50
    assert [r["fqdn"] for r in rows if not r["may_be_noise"] and results[r["fqdn"]].state == "NOISE"] == []
    assert (
        "OTHER_BRAND" in results["meta-framex-24f.pages.dev"].flags
        and results["meta-framex-24f.pages.dev"].state == "REVIEW"
    )


def _scoring(**risk):
    import copy

    cfg = copy.deepcopy(SCORING)
    cfg["points"]["risk"].update(risk)
    return cfg


def test_age_and_cert_thresholds_come_from_config():
    look = {
        "brand": "aramex",
        "keyword": "aramex",
        "label": "aramax",
        "method": "edit-distance",
        "position": "registrable",
        "restricted_zone": False,
        "context": "none",
        "context_words": [],
    }
    facts = _facts(look, age_days=10, cert_age_days=3)

    default = assess("aramax-x.com", facts, [], None, [], BRANDS, SCORING)
    moved = assess("aramax-x.com", facts, [], None, [], BRANDS, _scoring(age_recent_days=5, cert_recent_days=1))

    assert any(row.startswith("+2 domain age") for row in default.components["breakdown"])
    assert any(row.startswith("+1 certificate") for row in default.components["breakdown"])
    assert not any(row.startswith("+2 domain age") for row in moved.components["breakdown"])
    assert not any("certificate" in row and row.startswith("+") for row in moved.components["breakdown"])


def test_short_keyword_penalty_prefers_brand_prior_points_over_config_default():
    from dataclasses import replace

    look = {
        "brand": "du",
        "keyword": "du",
        "label": "du",
        "method": "token",
        "position": "subdomain",
        "restricted_zone": False,
        "context": "none",
        "context_words": [],
    }
    brands = [replace(b, prior_points={"du": -2.5}) if b.id == "du" else b for b in BRANDS]

    default = assess("du.evil.com", _facts(look), [], None, [], BRANDS, SCORING)
    prior = assess("du.evil.com", _facts(look), [], None, [], brands, SCORING)

    assert default.components["B"] == 2 + SCORING["points"]["brand"]["short_keyword_prior"]
    assert prior.components["B"] == 2 - 2.5


def test_scoring_py_has_no_numeric_thresholds():
    import ast

    tree = ast.parse(Path("scamshield/scoring.py").read_text(encoding="utf-8"))
    numbers = {
        n.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool)
    }

    assert numbers <= {0, 1, 2}  # 2 = digits of round(coverage, 2)


def test_confirmed_edge_gives_r4_points_and_feed_edge_half(tmp_path=None):
    look = {
        "brand": "aramex",
        "keyword": "aramex",
        "label": "aramex-x",
        "method": "token",
        "position": "registrable",
        "restricted_zone": False,
        "context_words": [],
    }
    edge = Edge(
        "aramex-x.com", "scam.example", "name_template", "aramex-<hex>", 0.5, 0.8, "same pattern", [1, 2], "strong"
    )

    base = _assess("aramex-x.com", _facts(look)).components["R"]
    confirmed = _assess("aramex-x.com", _facts(look), edges=[edge], neighbours=["scam.example"])
    listed = assess("aramex-x.com", _facts(look), [edge], None, [], BRANDS, SCORING, (), ["scam.example"])

    assert (
        confirmed.components["R"] - base == SCORING["points"]["risk"]["edge_confirmed"]
        and "GUARD:G2" in confirmed.flags
    )
    assert listed.components["R"] - base == SCORING["points"]["risk"]["edge_in_feed"] and "GUARD:G2" not in listed.flags


def test_weak_edge_gives_no_points():
    look = {
        "brand": "aramex",
        "keyword": "aramex",
        "label": "aramex-x",
        "method": "token",
        "position": "registrable",
        "restricted_zone": False,
        "context_words": [],
    }
    edge = Edge("aramex-x.com", "scam.example", "ip", "1.2.3.4", 0.5, 0.2, "weak", [1], "weak")

    assert (
        _assess("aramex-x.com", _facts(look), edges=[edge], neighbours=["scam.example"]).components["R"]
        == _assess("aramex-x.com", _facts(look)).components["R"]
    )


def test_hosting_subdomain_age_is_not_counted_as_old_or_young():
    look = {
        "brand": "aramex",
        "keyword": "aramex",
        "label": "aramex-b09d96",
        "method": "token",
        "position": "subdomain",
        "restricted_zone": False,
        "context_words": [],
    }

    old = _assess("aramex-b09d96.ingress-bonde.ewp.live", _facts(look, age_days=1640))
    young = _assess("aramex-b09d96.ingress-bonde.ewp.live", _facts(look, age_days=5))

    assert old.components["R"] == young.components["R"] and "age of the hosting domain not counted" in " ".join(
        old.components["breakdown"]
    )
    assert old.components["reason"] != "old established domain, weak brand-fit, no risk evidence"


def test_microsoft_proxy_reflection_of_an_official_domain_is_official():
    for host in (
        "uaepass.ae.mcas.ms",
        "uaepass.ae.admin-mcas.ms",
        "uaepass.ae.mcas-df.ms",
        "uaepass.ae.admin-mcas-df.ms",
    ):
        assert _assess(host, _facts()).state == "OFFICIAL"


def test_dev_subdomain_lowers_brand_points_but_keeps_the_name_queued():
    """beta-etisalat.ipixsolutions.net: a vendor's staging copy was REVIEW_HIGH; it is lowered, never dropped."""
    dev = _assess(
        "beta-etisalat.ipixsolutions.net",
        _facts(match("beta-etisalat.ipixsolutions.net", BRANDS, "feed"), resolves=True, age_days=5000),
    )
    real = _assess(
        "etisalat-portal.ipixsolutions.net",
        _facts(match("etisalat-portal.ipixsolutions.net", BRANDS, "feed"), resolves=True, age_days=5000),
    )
    assert dev.components["B"] == real.components["B"] - 2
    assert any("dev/staging word `beta`" in row for row in dev.components["breakdown"])
    assert dev.state != "NOISE"


def test_parked_page_name_is_no_brand_evidence():
    """talabat.eat: a for-sale page names the domain itself; that name-only page hit lifted it to REVIEW_HIGH."""
    stamp = NOW.isoformat().replace("+00:00", "Z")
    facts = _facts(match("talabat.eat", BRANDS), resolves=True, age_days=2)
    facts += [
        FactRow("snapshot_brand", {"brand": "talabat", "via": ["name"]}, "snapshot", None, stamp, "ok", id=90),
        FactRow(
            "snapshot_page", {"title": "talabat.eat", "parked": "is parked free"}, "snapshot", None, stamp, "ok", id=91
        ),
    ]
    parked = _assess("talabat.eat", facts)
    assert parked.components["band"] == "GRAY_LOW" and not any(
        "page shows" in row for row in parked.components["breakdown"]
    )
    facts[-1] = FactRow(
        "snapshot_page", {"title": "Talabat food order"}, "snapshot", None, stamp, "ok", id=91
    )  # a title that is only the host is no brand either
    assert any("page shows Talabat name" in row for row in _assess("talabat.eat", facts).components["breakdown"])


@pytest.mark.parametrize("host", ["library.smsa.org.au", "mofa.gov.tw.mcas.ms"])
def test_foreign_institution_named_like_a_brand_is_noise(host):
    assert _assess(host, _facts(match(host, BRANDS), resolves=True)).components["band"] == "NOISE"
