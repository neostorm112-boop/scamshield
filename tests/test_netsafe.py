import asyncio

import dns.resolver
import pytest

from scamshield.contracts import NormalizedURL, Rejection


class _Answer:
    def __init__(self, *values):
        self.rrset = type("RRSet", (), {"ttl": 300})()
        self._values = values

    def __iter__(self):
        return iter(self._values)


class _Resolver:
    async def resolve(self, host, record_type):
        if record_type == "A":
            return _Answer("93.184.216.34")
        if record_type == "AAAA":
            raise dns.resolver.NoAnswer
        raise AssertionError(record_type)


def test_check_url_normalizes_domain_and_resolves_public_address(monkeypatch):
    from scamshield import netsafe

    monkeypatch.setattr(netsafe, "_resolver", lambda: _Resolver())
    result = asyncio.run(netsafe.check_url("Example.COM/path?x=1"))

    assert isinstance(result, NormalizedURL)
    assert result.url == "https://example.com/path?x=1"
    assert result.fqdn == "example.com"
    assert result.registrable == "example.com"
    assert "scheme added (https)" in result.notes


@pytest.mark.parametrize(
    "raw",
    ["http://127.0.0.1", "http://[::1]", "http://10.0.0.1", "http://169.254.169.254", "http://100.64.0.1"],
)
def test_check_url_blocks_non_public_ip_literals(raw):
    from scamshield import netsafe

    result = asyncio.run(netsafe.check_url(raw))

    assert isinstance(result, Rejection)
    assert result.code == "PRIVATE_ADDRESS"
    assert (
        result.message
        == "Blocked: this link points to a private or local network address. Only public internet sites can be checked."
    )


def test_check_url_blocks_localhost_before_resolution():
    from scamshield import netsafe

    result = asyncio.run(netsafe.check_url("https://localhost/"))

    assert isinstance(result, Rejection)
    assert result.code == "LOCALHOST"


@pytest.mark.parametrize("raw", ["javascript:alert(1)", "file:///tmp/a", "mailto:test@example.com", ""])
def test_check_url_rejects_non_web_links(raw):
    from scamshield import netsafe

    result = asyncio.run(netsafe.check_url(raw))

    assert isinstance(result, Rejection)
    assert (
        result.message == "This is not a web link. Paste a link starting with http(s):// or a domain like example.com."
    )


def test_check_url_rejects_non_standard_port(monkeypatch):
    from scamshield import netsafe

    result = asyncio.run(netsafe.check_url("https://example.com:8443"))

    assert isinstance(result, Rejection)
    assert result.code == "BAD_PORT"
    assert result.message == "Only ports 80 and 443 are checked."
