from pathlib import Path

import yaml

from scamshield.config import load_brands
from scamshield.enrich.lookalike import fact_value, match, smishing_pattern

BRANDS = load_brands(Path("config/brands.yaml"))
GOLDEN = yaml.safe_load(Path("tests/fixtures/smishing_golden.yaml").read_text(encoding="utf-8"))


def test_pattern_catches_uae_word_on_cheap_tld_with_random_name():
    for fqdn in GOLDEN["pattern_fake"]:
        hit = smishing_pattern(fqdn)
        assert hit and hit["method"] == "smishing_pattern" and hit["brand"] is None, fqdn
    hit = smishing_pattern("dubai.aeizt.top")
    assert (hit["context_words"], hit["label"], hit["tld"]) == (["dubai"], "aeizt", "top")


def test_pattern_needs_uae_word_cheap_tld_and_random_name():
    assert smishing_pattern("dubai.aeizt.com") is None  # TLD not cheap
    assert smishing_pattern("dubai.bakery.top") is None  # real word
    assert smishing_pattern("uae-fine.top") is None  # only UAE words, nothing random
    assert smishing_pattern("dubai.xcb.top") is None  # root shorter than 4
    for fqdn in [
        "dubai.sports.top",
        "dubai.events.shop",
        "dubai.films.site",
        "uae.trends.top",
        "abudhabi.queue.top",
        "dubai.beauty.shop",
    ]:
        assert smishing_pattern(fqdn) is None, fqdn  # ordinary English words pass the run rule
    for fqdn in ["dubai.flynn.top", "dubai.kfcs.top"]:
        assert smishing_pattern(fqdn) is None, (
            fqdn
        )  # y is a vowel; 4 letters without a digit is an acronym, not a random name
    assert smishing_pattern("uae-xkq9.top")["label"] == "xkq9"  # UAE word as a name token


def test_names_without_uae_word_are_not_catchable_by_name():
    for fqdn in GOLDEN["not_catchable_by_name"]:
        assert smishing_pattern(fqdn) is None and match(fqdn, BRANDS) is None, fqdn


def test_hard_negatives_match_nothing():
    assert len(GOLDEN["legit"]) >= 10
    for fqdn in GOLDEN["legit"]:
        assert match(fqdn, BRANDS) is None and smishing_pattern(fqdn) is None, fqdn


def test_plain_parkin_needs_uae_or_payment_context():
    assert match("parkin-ae.mom", BRANDS)["brand"] == "parkin"
    assert match("parkin-dubai.top", BRANDS)["brand"] == "parkin"
    assert match("pay-parkin.top", BRANDS)["brand"] == "parkin"
    assert match("parkin.shop", BRANDS) is None
    assert match("parking-ae.top", BRANDS) is None


def test_long_keyword_typo_squat_by_prefix_and_scaled_distance():
    assert match("dubaipoit.com", BRANDS)["method"] == "edit-distance"
    assert match("emiratesnbd-secure.site", BRANDS)["brand"] == "enbd"  # not misread as emiratespost
    assert match("dubaipark.com", BRANDS) is None


def test_pattern_is_gray_low_with_plain_reason():
    from datetime import datetime

    from scamshield.contracts import FactRow
    from scamshield.scoring import assess
    from scamshield.web.view import _fact_line

    stamp = "2026-11-20T10:00:00Z"
    fqdn = "dubai.aeizt.top"
    value = fact_value(smishing_pattern(fqdn))
    facts = [
        FactRow("lookalike", value, "lookalike", None, stamp, "ok", id=1),
        FactRow("dns_a", {}, "t", None, stamp, "missing", id=2),
        FactRow("ip_asn", {}, "t", None, stamp, "missing", id=3),
        FactRow("in_feed", {"listed": False}, "t", None, stamp, "ok", id=4),
        FactRow("created_at", {}, "t", None, stamp, "missing", id=5),
    ]
    scoring = yaml.safe_load(Path("config/scoring.yaml").read_text(encoding="utf-8"))

    result = assess(fqdn, facts, [], None, [], BRANDS, scoring)

    assert result.components["band"] == "GRAY_LOW"
    assert result.components["reason"] == "Smishing pattern — target unclear" and result.state == "REVIEW"
    line = _fact_line(
        {
            "id": 1,
            "type": "lookalike",
            "value": value,
            "status": "ok",
            "source": "lookalike",
            "fetched_at": stamp,
            "data_mode": "LIVE",
        },
        {},
        datetime.fromisoformat(stamp[:-1]),
    )
    assert "dubai" in line["text"] and "aeizt" in line["text"] and "cheap .top" in line["text"]
