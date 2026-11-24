"""Complete the official domains of every brand in config/brands.yaml, with proof. No AI, official sites only.

    python -m scamshield.tools.harvest_official [--dry-run]

The domains already in brands.yaml are the trust root. For each one we read (1) the TLS certificate SAN names of
https://<d> and https://www.<d>, (2) the host names linked from its homepage. A new domain is ACCEPTED when it is in the SAN
of an official certificate, or when it is linked from the official homepage and its own certificate organisation names the
brand; any other brand-looking link goes to REVIEW. Candidate sites are never opened (a TLS handshake for the organisation
of a linked host is the only contact). ACCEPTED go into brands.yaml with a comment, everything goes into the evidence file."""

from __future__ import annotations

import argparse
import re
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from scamshield.config import CONFIG_DIR, _yaml
from scamshield.enrich.lookalike import _ICANN

ROOT = Path(__file__).resolve().parents[2]
_HOST = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")
MAX_PAGE = 2_000_000


def san_names(cert: dict | None) -> set[str]:
    """DNS names of a getpeercert() dict; `*.x.com` becomes x.com."""
    names = (v.lower().removeprefix("*.") for k, v in (cert or {}).get("subjectAltName", ()) if k == "DNS")
    return {n for n in names if _HOST.fullmatch(n)}


def cert_org(cert: dict | None) -> str:
    return next((v for rdn in (cert or {}).get("subject", ()) for k, v in rdn if k == "organizationName"), "")


class _Links(HTMLParser):
    def __init__(self, base: str):
        super().__init__()
        self.base, self.hosts = base, set()

    def handle_starttag(self, tag, attrs):
        href = dict(attrs).get("href") if tag == "a" else None
        if href:
            host = (urlsplit(urljoin(self.base, href.strip())).hostname or "").lower().rstrip(".")
            if _HOST.fullmatch(host):
                self.hosts.add(host)


def link_hosts(html: str, base_url: str) -> set[str]:
    parser = _Links(base_url)
    parser.feed(html)
    return parser.hosts


def fetch_cert(host: str, timeout: float = 8) -> dict | None:
    """Certificate of host:443 (verified, so getpeercert() has the SAN list); None when unreachable or invalid."""
    try:
        with (
            socket.create_connection((host, 443), timeout) as sock,
            ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls,
        ):
            return tls.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return None


def fetch_page(domain: str, client: httpx.Client) -> tuple[str, str] | None:
    """(final url, html) of the official homepage, https only; None when neither <d> nor www.<d> answers."""
    for host in (domain, f"www.{domain}"):
        try:
            resp = client.get(f"https://{host}/")
        except httpx.HTTPError:
            continue
        if resp.status_code == 200 and "html" in resp.headers.get("content-type", ""):
            return str(resp.url), resp.text[:MAX_PAGE]
    return None


def _under(host: str, domains) -> bool:
    return any(host == d or host.endswith(f".{d}") for d in domains)


def _mentions(text: str, keywords: list[str]) -> bool:
    """Keyword inside the name; short keywords (du) only as a whole -/. separated token, as lookalike.match does."""
    tokens = re.split(r"[-.]", text)
    return any(k in text if len(k) >= 4 else k in tokens for k in keywords)


def _target(host: str, keywords: list[str]) -> str | None:
    """What to trust for a host: its registrable domain when that carries a brand keyword, else only the host itself
    (digital.mashreqbank.com -> mashreqbank.com, but brand.service-now.com stays one host and never trusts service-now.com)."""
    ext = _ICANN(host)
    if not ext.suffix or not ext.domain:
        return None
    return ext.top_domain_under_public_suffix if _mentions(ext.domain, keywords) else host


def org_matches(org: str, keywords: list[str]) -> bool:
    text = org.lower()
    return any(re.search(rf"\b{re.escape(k)}\b" if len(k) < 4 else rf"\b{re.escape(k)}", text) for k in keywords)


def propose(brand: dict, evidence: dict, generic: list[str], org_of) -> tuple[dict, dict]:
    """(accepted, review): domain -> proof text. evidence: {official domain: {"sans": {host: set}, "page": (url, hosts) | None}}.
    Shared certificates carry unrelated sites (adpolice.gov.ae shares one with the Chamber of Commerce), so a SAN name that
    does not mention the brand is only REVIEW."""
    known, keywords = brand["official_domains"], brand["keywords"]
    accepted, review = {}, {}

    def candidate(host):
        host = host.removeprefix("www.")
        if _under(host, known) or _under(host, generic):
            return None
        dom = _target(host, keywords)
        return None if not dom or _under(dom, known) else dom

    for item in evidence.values():
        for cert_host, names in item["sans"].items():
            for name in sorted(names):
                if dom := candidate(name):
                    proof = f"cert SAN of {cert_host} (name {name})"
                    if _mentions(name, keywords):
                        accepted.setdefault(dom, proof)
                    else:
                        review.setdefault(dom, f"{proof}, name does not mention the brand (shared certificate?)")
        page = item["page"]
        for host in sorted(page[1] if page else ()):
            dom = candidate(host)
            if not dom or dom in accepted or not _mentions(host, keywords):
                continue
            org = org_of(host)
            proof = f"link from {page[0]}"
            if org and org_matches(org, keywords):
                accepted[dom] = f"{proof}, own cert organisation '{org}'"
            else:
                review.setdefault(
                    dom,
                    f"{proof}, own cert organisation {org!r} does not name the brand"
                    if org
                    else f"{proof}, no readable cert",
                )
    accepted = {d: p for d, p in accepted.items() if not any(d != o and d.endswith(f".{o}") for o in accepted)}
    return accepted, {d: p for d, p in review.items() if d not in accepted and not _under(d, accepted)}


def harvest_brand(brand: dict, generic: list[str], client: httpx.Client) -> tuple[dict, dict, list[str]]:
    evidence, failed = {}, []
    for official in brand["official_domains"]:
        sans = {}
        for host in (official, f"www.{official}"):
            cert = fetch_cert(host)
            if cert:
                sans[host] = san_names(cert)
        page = fetch_page(official, client)
        failed += [f"{official}: no certificate"] * (not sans) + [f"{official}: homepage not readable"] * (not page)
        evidence[official] = {"sans": sans, "page": (page[0], link_hosts(page[1], page[0])) if page else None}
    accepted, review = propose(brand, evidence, generic, lambda host: cert_org(fetch_cert(host)))
    return accepted, review, failed


def apply_accepted(text: str, accepted: dict[str, dict[str, str]], today: str) -> str:
    """Add the accepted domains to official_domains and put the proof in a comment line above it."""
    out, current = [], None
    for line in text.splitlines():
        if m := re.match(r"- id: (\S+)", line):
            current = m.group(1)
        if current in accepted and (m := re.fullmatch(r"(\s*)official_domains: \[(.*)\]", line)):
            proof = "; ".join(f"{d} ({p})" for d, p in accepted[current].items())
            out.append(f"{m.group(1)}# added {today} by harvest_official: {proof}")
            line = f"{m.group(1)}official_domains: [{m.group(2)}, {', '.join(accepted[current])}]"
        out.append(line)
    return "\n".join(out) + "\n"


def render_evidence(results: dict, today: str) -> str:
    lines = [
        f"# Official domains harvest, {today}",
        "",
        "Trust root: the domains already in config/brands.yaml. Sources: TLS certificate SAN of the official domain (strong proof),",
        "links on the official homepage (accepted only when the linked host's own certificate organisation names the brand).",
        "ACCEPTED are written to brands.yaml (verified_by stays null). REVIEW are NOT written: a maintainer decides.",
        "",
        "| brand | accepted | review | problems |",
        "|---|---|---|---|",
    ]
    lines += [f"| {b} | {len(r['accepted'])} | {len(r['review'])} | {len(r['failed'])} |" for b, r in results.items()]
    for title, key in (
        ("ACCEPTED (written to brands.yaml)", "accepted"),
        ("REVIEW (a maintainer decides, not written)", "review"),
    ):
        lines += ["", f"## {title}", "", "| brand | domain | proof | date |", "|---|---|---|---|"]
        lines += [f"| {b} | {d} | {p} | {today} |" for b, r in results.items() for d, p in r[key].items()]
    lines += ["", "## Problems (official domain without readable certificate or homepage)", ""]
    lines += [f"- {b}: {f}" for b, r in results.items() for f in r["failed"]]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print the evidence, do not write files")
    ap.add_argument("--today", default=date.today().isoformat())
    args = ap.parse_args(argv)
    path = CONFIG_DIR / "brands.yaml"
    brands = _yaml(path)
    generic = [d.lower() for d in _yaml(CONFIG_DIR / "harvest.yaml")["third_party"]]
    headers = {"User-Agent": "Mozilla/5.0 (compatible; scamshield-harvest; official sites only)"}
    with httpx.Client(timeout=10, follow_redirects=True, headers=headers) as client, ThreadPoolExecutor(8) as pool:
        done = list(pool.map(lambda b: harvest_brand(b, generic, client), brands))
    results = {b["id"]: {"accepted": a, "review": r, "failed": f} for b, (a, r, f) in zip(brands, done, strict=True)}
    report = render_evidence(results, args.today)
    if args.dry_run:
        print(report)
        return 0
    evidence_file = ROOT / f"docs/evidence/official-domains-{args.today}.md"
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    evidence_file.write_text(report, encoding="utf-8")
    path.write_text(
        apply_accepted(
            path.read_text(encoding="utf-8"),
            {b: r["accepted"] for b, r in results.items() if r["accepted"]},
            args.today,
        ),
        encoding="utf-8",
    )
    print(
        f"accepted {sum(len(r['accepted']) for r in results.values())}, review {sum(len(r['review']) for r in results.values())}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
