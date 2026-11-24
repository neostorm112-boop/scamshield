"""CertSpotter issuances for an exact domain and its subdomains; enrichment only, a cert never proves legitimacy."""

from __future__ import annotations

from urllib.parse import quote

from scamshield import sources
from scamshield.contracts import Ctx, Fact

_KINDS = ("certs",)


async def run(fqdn: str, ctx: Ctx) -> list[Fact]:
    fetched_at = ctx.now()
    cfg = ctx.settings.sources.get("certspotter")
    key = ctx.settings.secrets.get(getattr(cfg, "key_env", None) or "")
    url = f"https://api.certspotter.com/v1/issuances?domain={quote(fqdn)}&include_subdomains=true&expand=issuer"
    payload = await sources.fetch_json(ctx, "certspotter", url, {"Authorization": f"Bearer {key}"} if key else None)
    if isinstance(payload, sources.SourceError):
        return sources.error_facts(_KINDS, payload, fetched_at)
    try:
        issuances = sorted(payload, key=lambda item: item["not_before"])
        if not issuances:
            return sources.error_facts(_KINDS, sources.SourceError("certspotter", "http_404"), fetched_at)
        first, last = issuances[0], issuances[-1]
        value = {
            "count": len(issuances),
            "first_issued": first["not_before"],
            "last_issued": last["not_before"],
            "issuer": last["issuer"]["friendly_name"],
        }
    except (KeyError, TypeError):
        return sources.error_facts(_KINDS, sources.SourceError("certspotter", "bad_payload"), fetched_at)
    return [Fact("certs", value, "certspotter", first["not_before"], fetched_at, "ok")]
