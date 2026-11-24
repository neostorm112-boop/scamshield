import json
from pathlib import Path

import yaml

from scamshield.config import load_brands
from scamshield.enrich.lookalike import match
from scamshield.tools import harvest_official as h

FIX = Path("tests/fixtures/harvest")
GENERIC = ["facebook.com", "apple.com"]
BRAND = {"id": "mashreq", "official_domains": ["mashreq.com"], "keywords": ["mashreq"]}


def _cert():
    return json.loads((FIX / "mashreq_cert.json").read_text())


def _evidence(sans, hosts=(), page_url="https://www.mashreq.com/"):
    return {"mashreq.com": {"sans": {"www.mashreq.com": sans}, "page": (page_url, set(hosts))}}


def test_recorded_cert_san_and_org_and_wildcard_strip():
    assert h.san_names(_cert()) == {"mashreq.com", "mashreqbank.com"}
    assert h.cert_org(_cert()) == "MASHREQBANK PSC"
    assert h.san_names(
        {"subjectAltName": (("DNS", "*.a.com"), ("IP Address", "1.2.3.4"), ("DNS", "bad_name.com"))}
    ) == {"a.com"}
    assert h.san_names(None) == set() and h.cert_org(None) == ""


def test_link_hosts_resolves_relative_and_skips_mailto():
    hosts = h.link_hosts((FIX / "page.html").read_text(), "https://www.mashreq.com/")
    assert hosts == {
        "www.mashreq.com",
        "digital.mashreqbank.com",
        "www.mashreqfun.shop",
        "mashreq-rewards.net",
        "www.facebook.com",
        "apps.apple.com",
        "news.example.com",
    }


def test_san_proof_accepts_registrable_domain_of_brand_name():
    accepted, review = h.propose(BRAND, _evidence(h.san_names(_cert())), GENERIC, lambda host: None)
    assert accepted == {"mashreqbank.com": "cert SAN of www.mashreq.com (name mashreqbank.com)"} and review == {}


def test_unrelated_san_name_and_third_parties_are_not_accepted():
    sans = {"mashreq.com", "chamber.ae", "x.facebook.com", "brand.service-now.com"}
    accepted, review = h.propose(BRAND, _evidence(sans), GENERIC, lambda host: None)
    assert accepted == {} and set(review) == {"chamber.ae", "brand.service-now.com"}


def test_host_on_third_party_platform_is_trusted_alone_not_the_platform():
    accepted, _ = h.propose(BRAND, _evidence({"mashreq.service-now.com"}), GENERIC, lambda host: None)
    assert accepted == {"mashreq.service-now.com": "cert SAN of www.mashreq.com (name mashreq.service-now.com)"}


def test_link_needs_matching_cert_org_else_review():
    hosts = h.link_hosts((FIX / "page.html").read_text(), "https://www.mashreq.com/")
    orgs = {"digital.mashreqbank.com": "Mashreqbank PSC", "www.mashreqfun.shop": "Some Agency LLC"}
    accepted, review = h.propose(BRAND, _evidence(set(), hosts), GENERIC, orgs.get)
    assert list(accepted) == ["mashreqbank.com"] and accepted["mashreqbank.com"].startswith(
        "link from https://www.mashreq.com/, own cert organisation"
    )
    assert set(review) == {"mashreqfun.shop", "mashreq-rewards.net"}
    assert "Some Agency LLC" in review["mashreqfun.shop"] and "no readable cert" in review["mashreq-rewards.net"]


def test_short_keyword_matches_whole_token_only():
    assert h._mentions("du.com", ["du"]) and h._mentions("my-du.com", ["du"])
    assert not h._mentions("education.com", ["du"]) and not h._mentions("dubai.ae", ["du"])


def test_apply_accepted_adds_domain_and_comment_and_keeps_rest(tmp_path):
    text = "- id: rta\n  official_domains: [rta.ae]\n  verified_by: null\n\n- id: mashreq\n  official_domains: [mashreq.com]\n  verified_by: null\n"
    out = h.apply_accepted(text, {"mashreq": {"mashreqbank.com": "cert SAN of mashreq.com"}}, "2026-11-20")
    assert out == (
        "- id: rta\n  official_domains: [rta.ae]\n  verified_by: null\n\n- id: mashreq\n"
        "  # added 2026-11-20 by harvest_official: mashreqbank.com (cert SAN of mashreq.com)\n"
        "  official_domains: [mashreq.com, mashreqbank.com]\n  verified_by: null\n"
    )
    assert yaml.safe_load(out)[1]["official_domains"] == ["mashreq.com", "mashreqbank.com"]


def test_brands_yaml_mashreq_online_bank_is_official_and_fakes_still_match():
    brands = load_brands(Path("config/brands.yaml"))
    assert match("digital.mashreqbank.com", brands) is None
    assert match("rnashreq-bank.com", brands)["brand"] == "mashreq"
    assert match("mashreqbank-login.top", brands)["brand"] == "mashreq"
    assert all(b.verified_by is None for b in brands)
