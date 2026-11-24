"""The card must agree with itself: the risk number adds up from the listed points,
and every registration age on one card is counted from the same moment with the same wording."""

from datetime import UTC, datetime

from scamshield.web import view

NOW = datetime(2026, 11, 23, 9, 0, tzinfo=UTC)
CAREEM = {
    "B": 5,
    "R": 6.5,
    "P": 11.5,
    "band": "FURTHER",
    "reason": "enough brand-fit and risk evidence",
    "checks": 5,
    "breakdown": [
        "+3 brand in name",
        "+2 page shows Careem name on a non-official domain",
        "+2 domain age 2 d",
        "+1 certificate issued within 7 days",
        "+0.5 resolves",
        "+3 page offers jobs or visas and asks to contact via WhatsApp/Telegram",
    ],
}


def _ctx(facts, comp=None, flags=(), risk=0.4, now=NOW):
    domain = {
        "fqdn": "t.example",
        "brand_id": None,
        "state": "REVIEW_HIGH",
        "risk_score": risk,
        "found_by": "feeds",
        "first_seen_at": "2026-11-22T08:00:00Z",
    }
    full = [
        {
            "id": i,
            "source": "x",
            "fetched_at": "2026-11-22T08:00:00Z",
            "data_mode": "LIVE",
            "error": None,
            "status": "ok",
            **f,
        }
        for i, f in enumerate(facts, 1)
    ]
    assessment = {"flags": list(flags), "components": comp, "at": "2026-11-22T10:57:23Z"} if comp is not None else None
    return view.case_context(domain, full, assessment, None, {"poll": False, "text": None}, [], {}, now)


def test_risk_number_is_shown_as_the_sum_of_the_listed_points():
    """careemglobal.com: risk 96 next to points that add up to 11.5; the card never said that 12 points make 100."""
    ctx = _ctx([], CAREEM, risk=11.5 / 12)
    assert ctx["risk"] == 96
    assert ctx["points_total"] == "= 11.5 points; 12 points or more = risk 100, so 11.5 points = risk 96"


def test_points_total_caps_at_100_and_floors_at_0():
    assert _ctx([], {**CAREEM, "P": 15}, risk=1.0)["points_total"].endswith("so 15 points = risk 100")
    assert _ctx([], {**CAREEM, "P": -1.5}, risk=0.0)["points_total"].endswith("so -1.5 points = risk 0")
    assert _ctx([], None)["points_total"] is None


SALIK_TEXT = "Skip to content\n\nsalik.enterprises\n\nBlog\nHello world!\n\nWelcome to WordPress. This is your first post.\nsalik.enterprises\nBlog\nAbout"


def test_page_that_only_prints_its_own_address_shows_no_brand():
    """salik.enterprises: a blank WordPress whose site title is its own host name was scored 'page shows Salik name'."""
    from scamshield import config, snapshot

    s = config.load()
    cfg = s.scoring["snapshot"]
    assert snapshot.brand_shown("salik.enterprises", SALIK_TEXT, {}, "salik.enterprises", s.brands, {}, cfg) is None
    assert (
        snapshot.brand_shown(
            "x", "Visit https://www.salik.enterprises/pay today", {}, "salik.enterprises", s.brands, {}, cfg
        )
        is None
    )
    assert (
        snapshot.brand_shown("Salik toll top-up", SALIK_TEXT, {}, "salik.enterprises", s.brands, {}, cfg)["brand"]
        == "salik"
    )
    assert (
        snapshot.brand_shown("Pay at salik.ae", "", {}, "salik.enterprises", s.brands, {}, cfg)["brand"] == "salik"
    )  # the official address is still the brand


def test_stored_name_only_page_hit_that_echoes_the_host_is_not_counted():
    """Old snapshot_brand facts stay in the DB: scoring re-reads the page and drops the echo, and the card stops listing it as a reason."""
    from scamshield.contracts import FactRow
    from scamshield.enrich.lookalike import match
    from tests.test_scoring import BRANDS, _assess, _facts
    from tests.test_scoring import NOW as SCORING_NOW

    stamp = SCORING_NOW.isoformat().replace("+00:00", "Z")
    facts = _facts(match("salik.enterprises", BRANDS), resolves=True, age_days=1)
    facts += [
        FactRow(
            "snapshot_page",
            {"title": "salik.enterprises", "final_url": "https://salik.enterprises/", "text": SALIK_TEXT},
            "snapshot",
            None,
            stamp,
            "ok",
            id=90,
        ),
        FactRow("snapshot_brand", {"brand": "salik", "via": ["name"]}, "snapshot", None, stamp, "ok", id=91),
    ]
    echo = _assess("salik.enterprises", facts)
    assert (
        not any("page shows" in row for row in echo.components["breakdown"]) and "PAGE_BRAND_NOT_COUNTED" in echo.flags
    )
    facts[-2] = FactRow(
        "snapshot_page",
        {"title": "Salik toll top-up", "final_url": "https://salik.enterprises/", "text": ""},
        "snapshot",
        None,
        stamp,
        "ok",
        id=90,
    )
    real = _assess("salik.enterprises", facts)
    assert (
        any("page shows Salik name" in row for row in real.components["breakdown"])
        and "PAGE_BRAND_NOT_COUNTED" not in real.flags
    )

    lines = [{"type": "snapshot_brand", "value": {"brand": "salik", "via": ["name"]}}]
    shown = _ctx(lines, {**CAREEM, "breakdown": echo.components["breakdown"]}, echo.flags)
    assert not any("Page shows" in r["text"] for r in shown["reasons"])
    assert any("not counted" in row["text"] for g in shown["groups"] for row in g["rows"])


def _phrases(born: str, ingested: str, now: datetime) -> list[str]:
    facts = [{"type": "created_at", "value": {"date": born}}]
    ctx = _ctx(facts, now=now)
    full = [
        {"id": 1, "source": "rdap", "fetched_at": ingested, "data_mode": "LIVE", "error": None, "status": "ok", **f}
        for f in facts
    ]
    line = view.timeline({"found_by": "nrd", "first_seen_at": ingested}, full, ingested, now)
    return [ctx["reasons"][0]["text"], *[f"{p['label']} {p['text']}" for p in line]]


def test_registration_age_uses_one_clock_and_one_wording():
    """salik.enterprises: 'Registered 35 h ago' in the timeline and 'Registered 2 days ago' in the reasons on the same card."""
    salik = _phrases("2026-11-21T08:50:20.132Z", "2026-11-22T10:12:00Z", datetime(2026, 11, 22, 20, 0, tzinfo=UTC))
    assert salik[0] == "Registered 35 h ago (21 Nov 2026)" and salik[1] == "Registered 35 h ago"
    assert salik[2].endswith("(25 h after registration)")
    careem = _phrases(
        "2026-11-20T02:54:52Z", "2026-11-22T08:30:00Z", NOW
    )  # 78 h before NOW, found 53.6 h after registration
    assert careem[0] == "Registered 3 days ago (20 Nov 2026)" and careem[1] == "Registered 20 Nov"
    assert careem[2].endswith("(2 days after registration)")


def test_one_formatter_for_every_age():
    assert [view.age_text(h * 3600) for h in (0.5, 1, 47.9, 48, 71.9, 72)] == [
        "under 1 h",
        "1 h",
        "47 h",
        "2 days",
        "2 days",
        "3 days",
    ]
