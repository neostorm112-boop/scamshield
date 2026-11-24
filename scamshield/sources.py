"""Single gate to third-party HTTP sources: failures come back as SourceError data, never as exceptions."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

from scamshield import netsafe
from scamshield.contracts import Ctx, Fact


@dataclass
class SourceError:
    source: str
    reason: str  # disabled, budget, timeout, http_429, http_5xx, http_<code>, unreachable, bad_payload, bad_redirect


_REDIRECTS = {301, 302, 303, 307, 308}
_next_slot: dict[
    str, float
] = {}  # per source: earliest monotonic time of the next request (min_interval_s / backoff after 429)


async def _pace(source: str, interval: float) -> None:
    """Space requests to one source at least `interval` s apart (rdap.org allows 10 per 10 s per IP). Reserve the slot before
    sleeping, with no await in between, so parallel worker loops queue up instead of all firing at once."""
    now = time.monotonic()
    slot = max(now, _next_slot.get(source, 0.0))
    _next_slot[source] = slot + interval
    if slot > now:
        await asyncio.sleep(slot - now)


def _back_off(source: str, seconds: float) -> None:
    """After a 429 the source is left alone for `seconds`: hammering it on gets the IP blocked (rdap.org answers 403 to abuse)."""
    _next_slot[source] = max(_next_slot.get(source, 0.0), time.monotonic() + seconds)


async def _read_limited(
    http, url: str, timeout: float, max_bytes: int, headers: dict | None = None
) -> httpx.Response | SourceError:
    """Stream a big text body and stop as soon as it passes max_bytes (feeds are hundreds of thousands of lines)."""
    async with http.stream("GET", url, timeout=timeout, headers=headers) as response:
        if response.status_code != 200:
            return httpx.Response(response.status_code)
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) > max_bytes:
                return SourceError("", "too_large")
        validators = {
            k: v for k, v in getattr(response, "headers", {}).items() if k.lower() in ("etag", "last-modified")
        }
    return httpx.Response(200, content=bytes(body), headers=validators)


async def _get(
    ctx: Ctx,
    source: str,
    url: str,
    headers: dict | None = None,
    max_bytes: int | None = None,
    json_body: dict | None = None,
    redirects: int = 0,
) -> httpx.Response | SourceError:
    cfg = ctx.settings.sources.get(source)
    if cfg is not None and not getattr(cfg, "enabled", True):
        return SourceError(source, "disabled")
    if not await ctx.budget.take(source, ctx.pool):
        return SourceError(source, "budget")
    timeout = getattr(cfg, "timeout_s", 8)
    deadline = (
        cfg.extra.get("deadline_s") if cfg is not None else None
    )  # httpx timeouts are per read: a body that trickles never trips them
    interval = cfg.extra.get("min_interval_s") if cfg is not None else None
    if interval:
        await _pace(source, float(interval))
    seen = {url}
    for hop in range(redirects + 1):
        try:
            async with asyncio.timeout(deadline):
                if json_body is not None:
                    response = await ctx.http.post(url, timeout=timeout, headers=headers, json=json_body)
                else:
                    response = (
                        await ctx.http.get(url, timeout=timeout, headers=headers)
                        if max_bytes is None
                        else await _read_limited(ctx.http, url, timeout, max_bytes, headers)
                    )
        except (httpx.TimeoutException, TimeoutError):
            return SourceError(source, "timeout")
        except (httpx.HTTPError, OSError, ValueError):
            return SourceError(source, "unreachable")
        if isinstance(response, SourceError):
            return SourceError(source, response.reason)
        if not redirects or response.status_code not in _REDIRECTS:
            break
        # Every hop is a real request: https only, public host, no loop, and it spends budget like the first.
        target = urljoin(url, response.headers.get("location", ""))
        if (
            hop == redirects
            or target in seen
            or urlsplit(target).scheme != "https"
            or isinstance(await netsafe.check_url(target), netsafe.Rejection)
        ):
            return SourceError(source, "bad_redirect")
        if not await ctx.budget.take(source, ctx.pool):
            return SourceError(source, "budget")
        seen.add(target)
        url = target
    code = response.status_code
    if code == 304:
        return SourceError(source, "not_modified")
    if code == 429:
        backoff = cfg.extra.get("backoff_429_s") if cfg is not None else None
        if backoff:
            _back_off(source, float(backoff))
        return SourceError(source, "http_429")
    if code >= 500:
        return SourceError(source, "http_5xx")
    if code != 200:
        return SourceError(source, f"http_{code}")
    return response


async def fetch_text(ctx: Ctx, source: str, url: str, headers: dict | None = None) -> str | SourceError:
    response = await _get(ctx, source, url, headers)
    return response if isinstance(response, SourceError) else response.text


async def fetch_bytes(ctx: Ctx, source: str, url: str, max_bytes: int) -> bytes | SourceError:
    response = await _get(ctx, source, url, max_bytes=max_bytes)
    return response if isinstance(response, SourceError) else response.content


async def fetch_text_limited(
    ctx: Ctx, source: str, url: str, max_bytes: int, validators: dict | None = None
) -> str | SourceError:
    """validators: a per-URL dict this call keeps up to date ({url: {"etag": .., "last-modified": ..}}). With it the request is
    conditional, and an unchanged file comes back as SourceError "not_modified" without downloading it again."""
    known = (validators or {}).get(url, {})
    headers = {
        name: known[key]
        for key, name in (("etag", "If-None-Match"), ("last-modified", "If-Modified-Since"))
        if known.get(key)
    } or None
    response = await _get(ctx, source, url, headers, max_bytes=max_bytes)
    if isinstance(response, SourceError):
        return response
    if validators is not None:
        validators[url] = {k.lower(): v for k, v in response.headers.items() if k.lower() in ("etag", "last-modified")}
    return response.content.decode("utf-8", "replace")


async def fetch_json(
    ctx: Ctx, source: str, url: str, headers: dict | None = None, redirects: int = 0
) -> dict | list | SourceError:
    response = await _get(ctx, source, url, headers, redirects=redirects)
    if isinstance(response, SourceError):
        return response
    try:
        payload = response.json()
    except ValueError:
        return SourceError(source, "bad_payload")
    return payload if isinstance(payload, (dict, list)) else SourceError(source, "bad_payload")


async def post_json(
    ctx: Ctx, source: str, url: str, body: dict, headers: dict | None = None
) -> dict | list | SourceError:
    response = await _get(ctx, source, url, headers, json_body=body)
    if isinstance(response, SourceError):
        return response
    try:
        payload = response.json()
    except ValueError:
        return SourceError(source, "bad_payload")
    return payload if isinstance(payload, (dict, list)) else SourceError(source, "bad_payload")


_MISSING = {"http_404": "not_found", "bad_payload": "bad_payload"}  # source answered, but has no usable record

# ERRORS.md wording for each machine reason; the only place this text lives
_TEXT = {
    "budget": "request budget used",
    "timeout": "no answer (timeout)",
    "unreachable": "no answer",
    "http_429": "rate limit reached",
    "http_5xx": "source error",
    "disabled": "source disabled",
    "not_found": "no record",
    "bad_payload": "unreadable answer",
    "bad_redirect": "unsafe redirect",
    "too_large": "list larger than the size limit",
    "not_loaded": "phishing lists not loaded yet",
    "stale": "phishing lists are out of date",
    "checkpoint_invalid": "unreadable log checkpoint",
    "interrupted": "check was interrupted",
    "not_modified": "no changes since the last download",
}


def error_facts(kinds: tuple[str, ...], error: SourceError, fetched_at: str) -> list[Fact]:
    """Facts for a failed source call: one per expected kind, value {} and the machine reason kept (CONTRACTS)."""
    status, reason = ("missing", _MISSING[error.reason]) if error.reason in _MISSING else ("error", error.reason)
    return [Fact(kind, {}, error.source, None, fetched_at, status, reason) for kind in kinds]


def not_checked_text(source: str, reason: str | None) -> str:
    """Human row text for a fact whose status is not ok (ERRORS.md: "Not checked: <source> — ...")."""
    return f"Not checked: {source} — {reason_text(reason)}"


def reason_text(reason: str | None) -> str:
    return _TEXT.get(reason or "", reason or "no data")


def status_text(status: str) -> str:
    """Human text for a sources.status value; "error: <reason>" is translated, anything else passes through."""
    return reason_text(status.removeprefix("error: ")) if status.startswith("error: ") else status


def record_status(conn, name: str, now: str, error: str | None = None, off: bool = False) -> None:
    """Health row of a pulled source: ok, off (no key: quiet, not an error) or "error: <reason>"."""
    status = "off" if off else f"error: {error}" if error else "ok"
    conn.execute(
        """INSERT INTO sources (name, kind, data_mode, status, last_success_at, last_error, last_error_at) VALUES (?, 'connector', 'LIVE', ?, ?, ?, ?)
                 ON CONFLICT(name) DO UPDATE SET status = excluded.status, last_error = excluded.last_error, last_error_at = excluded.last_error_at,
                 last_success_at = COALESCE(excluded.last_success_at, sources.last_success_at)""",
        (name, status, now if status == "ok" else None, error, now if error else None),
    )
    conn.commit()
