import asyncio

from scamshield.contracts import Ctx, Settings


class _RRSet:
    ttl = 300


class _Answer:
    rrset = _RRSet()

    def __init__(self, *values):
        self.values = values

    def __iter__(self):
        return iter(self.values)


class _Resolver:
    async def resolve(self, name, record_type):
        answers = {
            ("example.com", "A"): _Answer("93.184.216.34"),
            ("example.com", "AAAA"): _Answer(),
            ("example.com", "CNAME"): _Answer(),
            ("example.com", "NS"): _Answer("a.iana-servers.net."),
            ("example.com", "MX"): _Answer(),
            # real Team Cymru shapes (checked with dig 2026-11-21): origin = ASN | prefix | CC | registry | allocated; AS<n> = ASN | CC | registry | allocated | name
            ("34.216.184.93.origin.asn.cymru.com", "TXT"): _Answer(
                '"15133 | 93.184.216.0/24 | US | arin | 2008-06-02"'
            ),
            ("AS15133.asn.cymru.com", "TXT"): _Answer('"15133 | US | arin | 1997-04-01 | EDGECAST, US"'),
        }
        return answers[(name, record_type)]


class _Budget:
    async def take(self, source, pool="auto"):
        return True

    async def remaining(self, source):
        return {}


def _ctx():
    return Ctx(
        settings=Settings([], {}, {}, {}, "", 0, "", "", {}),
        http=None,
        resolver=_Resolver(),
        budget=_Budget(),
        pool="manual",
        now=lambda: "2026-11-19T08:00:00Z",
    )


def test_dns_returns_provenanced_a_and_ns_facts():
    from scamshield.enrich import dns

    facts = asyncio.run(dns.run("example.com", _ctx()))

    by_type = {fact.type: fact for fact in facts}
    assert by_type["dns_a"].value == {"records": ["93.184.216.34"], "ttl": 300}
    assert by_type["dns_ns"].value["records"] == ["a.iana-servers.net"]
    assert all(fact.source == "dns" and fact.fetched_at == "2026-11-19T08:00:00Z" for fact in facts)
    assert all(fact.data_mode == "LIVE" for fact in facts)


def test_asn_returns_a_fact_for_each_resolved_ipv4():
    from scamshield.enrich import asn

    facts = asyncio.run(asn.run("example.com", _ctx()))

    assert len(facts) == 1
    assert facts[0].type == "ip_asn"
    assert facts[0].value == {"ip": "93.184.216.34", "asn": 15133, "prefix": "93.184.216.0/24", "name": "EDGECAST, US"}
    assert facts[0].source == "asn"
    assert facts[0].fetched_at == "2026-11-19T08:00:00Z"
