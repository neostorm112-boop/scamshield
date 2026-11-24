import asyncio

from scamshield.contracts import Ctx, Settings


class _Response:
    status_code = 200

    def json(self):
        return {
            "events": [{"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
        }


class _Http:
    async def get(self, url, **kwargs):
        return _Response()


class _Budget:
    async def take(self, source, pool="auto"):
        return True

    async def remaining(self, source):
        return {}


def test_rdap_returns_registration_and_registrar_fact():
    from scamshield.enrich import rdap

    ctx = Ctx(
        Settings(
            [], {"rdap": type("S", (), {"timeout_s": 8, "extra": {"max_redirects": 3}})()}, {}, {}, "", 0, "", "", {}
        ),
        _Http(),
        None,
        _Budget(),
        "manual",
        lambda: "2026-11-19T08:00:00Z",
    )
    facts = asyncio.run(rdap.run("example.com", ctx))

    assert facts[0].type == "created_at"
    assert facts[0].value["date"] == "2026-11-01T00:00:00Z"
    assert facts[1].value["name"] == "Example Registrar"


def test_rdap_broken_vcard_is_missing_bad_payload_without_exception():
    from scamshield.enrich import rdap

    class Resp:
        status_code = 200

        def json(self):
            return {"events": [], "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn"]]]}]}

    class Http:
        async def get(self, url, **kwargs):
            return Resp()

    ctx = Ctx(
        Settings(
            [], {"rdap": type("S", (), {"timeout_s": 8, "extra": {"max_redirects": 3}})()}, {}, {}, "", 0, "", "", {}
        ),
        Http(),
        None,
        _Budget(),
        "manual",
        lambda: "2026-11-19T08:00:00Z",
    )
    facts = asyncio.run(rdap.run("example.com", ctx))

    assert facts and all(f.status == "missing" and f.error == "bad_payload" for f in facts)


def _redirect_ctx(routes, monkeypatch):
    import httpx

    from scamshield import netsafe

    async def public(url):
        return object()

    monkeypatch.setattr(netsafe, "check_url", public)
    calls = []

    class Http:
        async def get(self, url, **kwargs):
            calls.append(url)
            status, location = routes[url]
            if status == 200:
                return httpx.Response(
                    200, json={"events": [{"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}]}
                )
            return httpx.Response(status, headers={"location": location})

    cfg = type("S", (), {"timeout_s": 8, "extra": {"max_redirects": 3}})()
    return Ctx(
        Settings([], {"rdap": cfg}, {}, {}, "", 0, "", "", {}),
        Http(),
        None,
        _Budget(),
        "manual",
        lambda: "2026-11-19T08:00:00Z",
    ), calls


def test_rdap_follows_recorded_302_to_registry_200(monkeypatch):
    from scamshield.enrich import rdap

    ctx, calls = _redirect_ctx(
        {
            "https://rdap.org/domain/fake.com": (302, "https://rdap.verisign.com/com/v1/domain/fake.com"),
            "https://rdap.verisign.com/com/v1/domain/fake.com": (200, ""),
        },
        monkeypatch,
    )
    facts = asyncio.run(rdap.run("fake.com", ctx))

    assert facts[0].status == "ok" and facts[0].value["date"] == "2026-11-01T00:00:00Z"
    assert len(calls) == 2


def test_rdap_bad_redirects_are_error_facts_not_exceptions(monkeypatch):
    from scamshield.enrich import rdap

    cases = {
        "loop": {"https://rdap.org/domain/a.com": (302, "https://rdap.org/domain/a.com")},
        "downgrade": {"https://rdap.org/domain/a.com": (302, "http://rdap.example/domain/a.com")},
        "too_many": {
            "https://rdap.org/domain/a.com": (302, "https://h1.example/"),
            **{f"https://h{i}.example/": (302, f"https://h{i + 1}.example/") for i in range(1, 6)},
        },
    }
    for routes in cases.values():
        ctx, calls = _redirect_ctx(routes, monkeypatch)
        facts = asyncio.run(rdap.run("a.com", ctx))
        assert facts and all(f.status == "error" and f.error == "bad_redirect" for f in facts)
        assert len(calls) <= 4


def test_rdap_asks_registrable_domain_for_hosting_subdomain(monkeypatch):
    from scamshield.enrich import rdap

    ctx, calls = _redirect_ctx({"https://rdap.org/domain/ewp.live": (200, "")}, monkeypatch)
    asyncio.run(rdap.run("aramex-b09d96.ingress-bonde.ewp.live", ctx))
    assert calls == ["https://rdap.org/domain/ewp.live"]


def _run_fixture(name, fqdn):
    import json
    from pathlib import Path

    from scamshield.enrich import rdap

    payload = json.loads((Path(__file__).parent / "fixtures" / "rdap" / name).read_text())

    class Resp:
        status_code = 200

        def json(self):
            return payload

    class Http:
        async def get(self, url, **kwargs):
            return Resp()

    ctx = Ctx(
        Settings(
            [], {"rdap": type("S", (), {"timeout_s": 8, "extra": {"max_redirects": 3}})()}, {}, {}, "", 0, "", "", {}
        ),
        Http(),
        None,
        _Budget(),
        "manual",
        lambda: "2026-11-19T08:00:00Z",
    )
    return asyncio.run(rdap.run(fqdn, ctx))


def test_rdap_registrar_name_from_recorded_com_and_live_responses():
    com, live = _run_fixture("example.com.json", "example.com"), _run_fixture("ewp.live.json", "ewp.live")

    assert com[1].value == {"name": "MarkMonitor Inc."}
    assert live[1].value == {"name": "NameCheap, Inc."}  # not the vCard version "4.0", not the reseller


def test_rdap_non_string_registrar_name_is_missing_fact():
    from scamshield.enrich import rdap

    assert (
        rdap._registrar({"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", ["a"]]]]}]})
        is None
    )


def test_rdap_keeps_registrar_abuse_email():
    from scamshield.enrich import rdap

    abuse = {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@registrar.example"]]]}
    payload = {
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "R"]]], "entities": [abuse]}]
    }
    assert rdap._abuse_email(payload) == "abuse@registrar.example"
    assert (
        rdap._abuse_email(
            {"entities": [{"roles": ["registrar"], "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", []]}]}]}
        )
        is None
    )


def test_rdap_odd_abuse_shapes_never_drop_registration_facts():
    from scamshield.enrich import rdap

    for abuse in (
        {"roles": ["abuse"], "vcardArray": "oops"},
        {"roles": ["abuse"], "vcardArray": ["vcard", ["email"]]},
        {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "a b@x.example"]]]},
    ):
        payload = {
            "events": [{"eventAction": "registration", "eventDate": "2026-11-01T00:00:00Z"}],
            "entities": [
                {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "R"]]], "entities": [abuse]}
            ],
        }

        class Resp:
            status_code = 200

            def json(self, payload=payload):
                return payload

        class Http:
            async def get(self, url, **kwargs):
                return Resp()

        ctx = Ctx(
            Settings(
                [],
                {"rdap": type("S", (), {"timeout_s": 8, "extra": {"max_redirects": 3}})()},
                {},
                {},
                "",
                0,
                "",
                "",
                {},
            ),
            Http(),
            None,
            _Budget(),
            "manual",
            lambda: "2026-11-19T08:00:00Z",
        )
        facts = asyncio.run(rdap.run("example.com", ctx))
        assert facts[0].value["date"] == "2026-11-01T00:00:00Z" and facts[1].value == {"name": "R"}


def test_rdap_abuse_email_skips_entity_without_email():
    from scamshield.enrich import rdap

    empty = {"roles": ["abuse"], "vcardArray": ["vcard", []]}
    good = {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@r.example"]]]}
    assert rdap._abuse_email({"entities": [{"roles": ["registrar"], "entities": [empty, good]}]}) == "abuse@r.example"


def _paced_ctx(status, extra):
    import httpx

    calls = []

    class Http:
        async def get(self, url, **kwargs):
            calls.append(asyncio.get_running_loop().time())
            return httpx.Response(status)

    ctx = Ctx(
        Settings([], {"paced": type("S", (), {"timeout_s": 8, "extra": extra})()}, {}, {}, "", 0, "", "", {}),
        Http(),
        None,
        _Budget(),
        "manual",
        lambda: "2026-11-22T08:00:00Z",
    )
    return ctx, calls


def test_min_interval_spaces_parallel_requests_to_one_source():
    """rdap.org allows 10 requests per 10 s per IP; three worker loops at once must queue up, not fire together."""
    from scamshield import sources

    sources._next_slot.clear()
    ctx, calls = _paced_ctx(200, {"min_interval_s": 0.2})

    async def burst():
        await asyncio.gather(*(sources.fetch_text(ctx, "paced", "https://example.com/") for _ in range(3)))

    asyncio.run(burst())
    from itertools import pairwise

    gaps = [b - a for a, b in pairwise(calls)]
    assert len(calls) == 3 and all(gap >= 0.18 for gap in gaps)


def test_429_pushes_next_request_back_by_backoff():
    from scamshield import sources

    sources._next_slot.clear()
    ctx, _ = _paced_ctx(429, {"min_interval_s": 0.01, "backoff_429_s": 30})
    result = asyncio.run(sources.fetch_text(ctx, "paced", "https://example.com/"))

    assert isinstance(result, sources.SourceError) and result.reason == "http_429"
    import time

    assert sources._next_slot["paced"] - time.monotonic() > 25
    sources._next_slot.clear()
