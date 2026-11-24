"""URL normalisation and SSRF-safe public-address checks."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

import dns.asyncresolver
import dns.exception
import tldextract

from scamshield.contracts import NormalizedURL, Rejection

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_ICANN_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)


_BAD_LINK = "This is not a web link. Paste a link starting with http(s):// or a domain like example.com."
_PRIVATE = "Blocked: this link points to a private or local network address. Only public internet sites can be checked."


def registrable_of(host: str) -> str:
    extracted = _EXTRACT(host)
    return ".".join(part for part in (extracted.domain, extracted.suffix) if part)


def icann_registrable_of(host: str) -> str:
    # RDAP knows only registry-level domains; hosting suffixes like ewp.live are not registrations.
    extracted = _ICANN_EXTRACT(host)
    return ".".join(part for part in (extracted.domain, extracted.suffix) if part)


def _resolver() -> dns.asyncresolver.Resolver:
    return dns.asyncresolver.Resolver()


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or ip in ipaddress.ip_network("100.64.0.0/10")
    )


async def _addresses(host: str, resolver: dns.asyncresolver.Resolver) -> list[str] | None:
    answers: list[str] = []
    found = False
    for record_type in ("A", "AAAA"):
        try:
            answer = await resolver.resolve(host, record_type)
            found = True
            answers.extend(str(value).rstrip(".") for value in answer)
        except (dns.exception.DNSException, OSError, ValueError):
            continue
    return answers if found else None


async def check_url(raw: str) -> NormalizedURL | Rejection:
    """Normalize a web URL and permit only hosts resolving exclusively to public IPs."""
    raw = raw.strip()
    if not raw:
        return Rejection("NOT_A_URL", _BAD_LINK)
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", raw) and not re.match(r"^https?://", raw, re.IGNORECASE):
        return Rejection("BAD_SCHEME", _BAD_LINK)
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError:
        return Rejection("NOT_A_URL", _BAD_LINK)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return Rejection("BAD_SCHEME", _BAD_LINK)
    if port is not None and port not in {80, 443}:
        return Rejection("BAD_PORT", "Only ports 80 and 443 are checked.")
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return Rejection("NOT_A_URL", _BAD_LINK)
    if host == "localhost" or host.endswith(".localhost"):
        return Rejection("LOCALHOST", _PRIVATE)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _is_public(str(literal)):
            return Rejection("PRIVATE_ADDRESS", _PRIVATE)
        addresses = [str(literal)]
    else:
        addresses = await _addresses(host, _resolver())
        if not addresses:
            return Rejection("UNRESOLVABLE", "Domain does not resolve (NXDOMAIN) — site may be down or not yet live.")
        if any(not _is_public(address) for address in addresses):
            return Rejection("PRIVATE_ADDRESS", _PRIVATE)
    registrable = registrable_of(host)
    if not registrable:
        return Rejection("NOT_A_URL", _BAD_LINK)
    netloc = host if port is None else f"{host}:{port}"
    notes = [] if "://" in raw else ["scheme added (https)"]
    if parsed.username or parsed.password:
        notes.append("credentials removed")
    return NormalizedURL(
        raw=raw,
        url=urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, "")),
        scheme=parsed.scheme,
        host=host,
        port=port or (443 if parsed.scheme == "https" else 80),
        fqdn=host,
        registrable=registrable,
        notes=notes,
    )


MOBILE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
