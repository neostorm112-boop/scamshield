"""DNS evidence collection; failed lookups are facts, never raised errors."""

from __future__ import annotations

import dns.exception
import dns.resolver

from scamshield.contracts import Ctx, Fact

_RECORDS = (("A", "dns_a"), ("AAAA", "dns_aaaa"), ("CNAME", "dns_cname"), ("NS", "dns_ns"), ("MX", "dns_mx"))


async def run(fqdn: str, ctx: Ctx) -> list[Fact]:
    fetched_at = ctx.now()
    facts = []
    for record_type, fact_type in _RECORDS:
        try:
            answer = await ctx.resolver.resolve(fqdn, record_type)
            values = [str(value).rstrip(".") for value in answer]
            ttl = getattr(getattr(answer, "rrset", None), "ttl", None)
            facts.append(Fact(fact_type, {"records": values, "ttl": ttl}, "dns", None, fetched_at, "ok"))
        except dns.resolver.NXDOMAIN:
            facts.append(Fact(fact_type, {}, "dns", None, fetched_at, "missing", "nxdomain"))
        except dns.exception.DNSException:
            facts.append(Fact(fact_type, {}, "dns", None, fetched_at, "missing", "no_answer"))
        except (OSError, ValueError):
            facts.append(Fact(fact_type, {}, "dns", None, fetched_at, "error", "resolver_error"))
    return facts
