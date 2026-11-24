"""RDAP registration evidence; registrant contacts are intentionally ignored."""

from __future__ import annotations

import re

from scamshield import sources
from scamshield.contracts import Ctx, Fact
from scamshield.netsafe import icann_registrable_of

_KINDS = ("created_at", "registrar")
_EMAIL = re.compile(r"[^\s@<>,;]{1,64}@[A-Za-z0-9.-]{1,255}")


def _registrar(payload: dict) -> str | None:
    for entity in payload.get("entities", []):
        if "registrar" in entity.get("roles", []):
            props = {
                prop[0]: prop[3] for prop in entity.get("vcardArray", [None, []])[1]
            }  # vCard also holds "version": "4.0"
            name = props.get("fn") or props.get("org")
            return name if isinstance(name, str) and name.strip() else None
    return None


def _abuse_email(payload: dict) -> str | None:
    """The registrar's own abuse mailbox (entity role "abuse" inside the registrar entity); registrant contacts stay ignored. Any odd shape -> None."""
    try:
        for entity in payload.get("entities", []):
            if "registrar" in entity.get("roles", []):
                for sub in entity.get("entities", []):
                    if "abuse" in sub.get("roles", []):
                        for prop in sub["vcardArray"][1]:
                            if prop[0] == "email" and isinstance(prop[3], str) and _EMAIL.fullmatch(prop[3]):
                                return prop[3]
    except (AttributeError, IndexError, KeyError, TypeError):
        pass
    return None


async def run(fqdn: str, ctx: Ctx) -> list[Fact]:
    fetched_at = ctx.now()
    payload = await sources.fetch_json(
        ctx,
        "rdap",
        f"https://rdap.org/domain/{icann_registrable_of(fqdn) or fqdn}",
        redirects=ctx.settings.sources["rdap"].extra["max_redirects"],
    )
    if isinstance(payload, sources.SourceError):
        return sources.error_facts(_KINDS, payload, fetched_at)
    try:
        created = next(
            (
                event.get("eventDate")
                for event in payload.get("events", [])
                if event.get("eventAction") == "registration"
            ),
            None,
        )
        registrar = _registrar(payload)
        abuse = _abuse_email(payload)
    except (AttributeError, IndexError, KeyError, TypeError):
        return _bad_payload(fetched_at)
    return [
        Fact(
            "created_at",
            {"date": created} if created else {},
            "rdap",
            created,
            fetched_at,
            "ok" if created else "missing",
        ),
        Fact(
            "registrar",
            ({"name": registrar, **({"abuse_email": abuse} if abuse else {})}) if registrar else {},
            "rdap",
            None,
            fetched_at,
            "ok" if registrar else "missing",
        ),
    ]


def _bad_payload(fetched_at: str) -> list[Fact]:
    return sources.error_facts(_KINDS, sources.SourceError("rdap", "bad_payload"), fetched_at)
