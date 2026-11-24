from scamshield.config import load_brands


def test_match_detects_typosquat_and_nested_brand_label():
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))

    assert match("e1isalat-pay.com", brands)["brand"] == "etisalat"
    assert match("aramex-1f3a9c.ingress-earth.ewp.live", brands)["brand"] == "aramex"


def test_match_ignores_official_excluded_and_random_domains():
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))

    assert match("rta.ae", brands) is None
    assert match("metamask.io", brands) is None
    assert match("7b2e5c4a-3a51-4d2d-acde-9bce01f9550a.example", brands) is None


def _golden():
    import yaml

    with open("tests/fixtures/lookalike_golden.yaml", encoding="utf-8") as f:
        return yaml.safe_load(f)


def test_golden_fakes_caught_with_right_brand_and_legit_never_match():
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    golden = _golden()

    assert len(golden["fake"]) >= 10 and len(golden["legit"]) >= 10
    for item in golden["fake"]:
        found = match(item["fqdn"], brands)
        assert found and found["brand"] == item["brand"], item["fqdn"]
        assert (found["method"], found["position"]) == (item["method"], item["position"]), item["fqdn"]
    for fqdn in golden["legit"]:
        assert match(fqdn, brands) is None, fqdn


def test_homoglyph_and_idn_methods_and_result_shape():
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))

    found = match("e1isalat-pay.com", brands)
    assert found["method"] == "homoglyph" and found["keyword"] == "etisalat" and found["mode"] == "ct"
    assert found["restricted_zone"] is False and found["context_words"] == ["pay"]
    assert match("pay-rta.online", brands)["context_words"] == ["pay"]
    assert match("pay-rta.online", brands)["context"] == "name"


def test_feed_mode_relaxation_and_misses():
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    feed = _golden()["feed"]

    for item in feed["hit"]:
        found = match(item["fqdn"], brands, mode="feed", url_path=item.get("url_path"))
        assert found and found["brand"] == item["brand"], item["fqdn"]
        assert (found["position"], found["context"], found["mode"]) == (item["position"], item["context"], "feed")
    for item in feed["miss"]:
        assert match(item["fqdn"], brands, mode="feed", url_path=item.get("url_path")) is None, item["fqdn"]
    for fqdn in ("rta.dogestocks.com", "du.ac.bd", "du.xyz"):
        assert match(fqdn, brands) is None, fqdn
    assert match("du.xyz", brands, url_path="/du-recharge/pay") is None  # CT mode ignores the path


def test_restricted_zone_flag_on_foreign_academic_zone():
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))

    found = match("etisalat.example.ac.bd", brands)
    assert found["restricted_zone"] is True and found["position"] == "subdomain"
    assert match("etisalat.example.ac.ae", brands)["restricted_zone"] is False


def test_match_is_fast_enough_for_ct_feed():
    import time

    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    names = [item["fqdn"] for item in _golden()["fake"]] + _golden()["legit"]
    names = (names + [f"mail-server-{i}.some-random-host-{i}.example.org" for i in range(40)]) * 30

    started = time.perf_counter()
    for name in names:
        match(name, brands)

    assert len(names) / (time.perf_counter() - started) >= 1000


def test_career_is_not_careem_but_real_careem_fakes_still_match():
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    for fqdn in (
        "freshcareernews.com",
        "careernowhq.com",
        "igniteyourcareernow.com",
        "realestatecareernight.com",
        "careernomadexperts.digital",
        "ai-careernexus441.pages.dev",
        "rwb-careernet.pqa.nl",
        "mysqleditor-careernerds.kinsta.cloud",
    ):
        found = match(fqdn, brands)
        assert not found or found["brand"] != "careem", fqdn
    for fqdn in ("careem-pay.com", "careem.ae-login.top", "carеem-pay.com", "carern-pay.com"):
        assert match(fqdn, brands)["brand"] == "careem", fqdn


def test_microsoft_proxy_reflection_of_an_official_domain_is_not_a_hit():
    from scamshield.enrich.lookalike import match, path_match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    for host in (
        "uaepass.ae.mcas.ms",
        "uaepass.ae.admin-mcas.ms",
        "uaepass.ae.mcas-df.ms",
        "uaepass.ae.admin-mcas-df.ms",
    ):
        assert match(host, brands) is None
        assert path_match(host, brands, "/uaepass/login") is None
    assert match("uaepass-login.com.mcas.ms", brands) is not None  # the proxy of a non-official name stays a lookalike


def test_darb_is_a_common_word_and_needs_context():
    """Every queued darb name was an Arabic site (darb = road/way): darb.care clinic, darb-academy, hezb-darb, d4rb.com."""
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    for fqdn in (
        "test.darb.care",
        "darb.care",
        "darb-academy.com",
        "hezb-darb.com",
        "d4rb.com",
        "darb-smartfollowup.com",
        "darb-albinaa.ly",
        "darb.minormakerslab.nl",
        "nogoum-darb.pages.dev",
    ):
        found = match(fqdn, brands)
        assert not found or found["brand"] != "darb", fqdn
    for fqdn in (
        "darb-toll-pay.com",
        "darb-ae.com",
        "d4rb-pay.com",
        "darb-qmobilitya.com",
        "darb.qmobilits.top",
        "darb-toll.com",
        "darb.uae-fines.top",
    ):
        assert match(fqdn, brands)["brand"] == "darb", fqdn
    assert match("darb.qmobility.ae", brands) is None  # official portal


def test_dev_word_in_subdomain_is_marked_and_real_subdomain_fakes_are_not():
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    hit = match("beta-etisalat.ipixsolutions.net", brands, "feed")
    assert hit["brand"] == "etisalat" and hit["position"] == "subdomain" and hit["dev_label"] == "beta"
    assert match("etisalat.staging.vendor.com", brands)["dev_label"] == "staging"
    for fqdn in ("etisalat-pay.evil.com", "etisalat.ae.verify-account.com", "etisalat-bill.com", "salik.pay-now.xyz"):
        assert "dev_label" not in match(fqdn, brands), fqdn
    assert "dev_label" not in match(
        "test.etisalat-bill.com", brands
    )  # brand in the registrable label: the subdomain word is not a vendor sign


def test_brand_glued_into_an_ordinary_english_word_is_not_a_hit():
    """A live run: "careem" inside care+email, care+employer, care+emergency ranked in the top 30."""
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    for fqdn in (
        "www.nationalsleepcareemail.com",
        "wellthcareemployer.com",
        "rapidcareemergencyplumberottawa.site",
        "covid.rapidcareemergency.com",
    ):
        found = match(fqdn, brands)
        assert not found or found["brand"] != "careem", fqdn
    for fqdn in ("careemglobal.com", "careem-pay.com", "mycareem.top", "careem-email.com", "careemail-careem.com"):
        assert match(fqdn, brands)["brand"] == "careem", fqdn  # a clean occurrence or a separate token still counts


def test_foreign_institution_and_proxy_reflection_of_a_foreign_government_are_restricted():
    """library.smsa.org.au (an Australian association) and mofa.gov.tw seen through Defender for Cloud Apps (mofa.gov.tw.mcas.ms)."""
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    for fqdn in ("library.smsa.org.au", "mofa.gov.tw.mcas.ms", "mofa.gov.tw.admin-mcas-df.ms"):
        found = match(fqdn, brands)
        assert found and found["restricted_zone"] and found["position"] == "registrable", fqdn
    assert (
        match("mofa-visa.com.mcas.ms", brands)["position"] == "registrable"
    )  # a non-official name seen through the proxy is still a lookalike


def test_word_exceptions_belong_to_one_keyword_and_open_org_zones_stay_normal():
    """The care+email exception must not cut other brands (dubaipolice+mail), and only org.au, not every org.xx, is restricted."""
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    for fqdn, brand in (
        ("dubaipolicemail.com", "dubaipolice"),
        ("adpolicemail.com", "adpolice"),
        ("virginmobilemail.com", "virginmobileae"),
    ):
        found = match(fqdn, brands)
        assert found and found["brand"] == brand, fqdn
    for fqdn in ("salik.org.uk", "careem.org.pk"):
        found = match(fqdn, brands, mode="feed")
        assert found and not found["restricted_zone"], fqdn


def test_aramex_inside_mexico_is_not_a_hit_but_separate_aramex_still_is():
    """luminaramexico.com and app.altharamexico.com ranked as Aramex (lumin-aramex-ico)."""
    from scamshield.enrich.lookalike import match

    brands = load_brands(__import__("pathlib").Path("config/brands.yaml"))
    for fqdn in ("luminaramexico.com", "app.altharamexico.com"):
        found = match(fqdn, brands)
        assert not found or found["brand"] != "aramex", fqdn
    for fqdn in ("aramex-mexico.com", "aramex-help.com", "aramexmexico.com"):
        assert match(fqdn, brands)["brand"] == "aramex", fqdn
