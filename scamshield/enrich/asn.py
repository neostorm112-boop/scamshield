"""IP-to-ASN evidence via Team Cymru's DNS service."""

from __future__ import annotations

import ipaddress

import dns.exception

from scamshield.contracts import Ctx, Fact


def _cymru_name(ip: str) -> str:
    return f"{'.'.join(reversed(ip.split('.')))}.origin.asn.cymru.com"


async def _txt(ctx: Ctx, name: str) -> list[str]:
    answer = await ctx.resolver.resolve(name, "TXT")
    return [part.strip() for part in str(next(iter(answer))).strip('"').split("|")]


async def _as_name(ctx: Ctx, number: int) -> str | None:
    """Network name from AS<n>.asn.cymru.com (ASN | CC | registry | allocated | name); None when it does not answer: the ASN fact stays."""
    try:
        return (await _txt(ctx, f"AS{number}.asn.cymru.com"))[4] or None
    except (IndexError, OSError, StopIteration, ValueError, dns.exception.DNSException):
        return None


async def run(fqdn: str, ctx: Ctx) -> list[Fact]:
    fetched_at = ctx.now()
    try:
        addresses = [str(answer) for answer in await ctx.resolver.resolve(fqdn, "A")]
    except (OSError, ValueError, dns.exception.DNSException):
        return [Fact("ip_asn", {}, "asn", None, fetched_at, "error", "dns_unavailable")]
    facts, names = [], {}
    for ip in addresses:
        try:
            if ipaddress.ip_address(ip).version != 4:
                continue
            parts = await _txt(ctx, _cymru_name(ip))  # ASN | prefix | CC | registry | allocated (no network name here)
            number = int(parts[0].split()[0])
            if number not in names:
                names[number] = await _as_name(ctx, number)
            value = {"ip": ip, "asn": number, "prefix": parts[1]}
            facts.append(
                Fact(
                    "ip_asn",
                    {**value, "name": names[number]} if names[number] else value,
                    "asn",
                    None,
                    fetched_at,
                    "ok",
                )
            )
        except (IndexError, OSError, StopIteration, ValueError, dns.exception.DNSException):
            facts.append(Fact("ip_asn", {"ip": ip}, "asn", None, fetched_at, "missing", "no_answer"))
    return facts or [Fact("ip_asn", {}, "asn", None, fetched_at, "missing", "no_ipv4")]
