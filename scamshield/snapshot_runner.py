"""One fresh Chromium context for one page; snapshot.py starts it as a subprocess and kills it after 25 s (ADR 0004).
No clicks, no typing. Job JSON on stdin, one result JSON line on stdout."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import re
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import async_playwright

from scamshield.netsafe import MOBILE_UA, _is_public, registrable_of

# No WebRTC in the page, and no Worker / SharedWorker (route_web_socket does not see sockets opened inside workers). The constructor throws, so nothing is opened;
# each attempt is remembered and shown as evidence (official sites use workers too, so an attempt does not stop the snapshot).
# WebSocket stays: real phishing kits use socket.io, so the page-level socket goes through route_web_socket, which lets public hosts through and stops private ones.
_FEATURES = ["RTCPeerConnection", "webkitRTCPeerConnection", "RTCDataChannel", "Worker", "SharedWorker"]
_INIT = f"""for (const n of {_FEATURES!r}) {{
  Object.defineProperty(window, n, {{configurable: true, value: function () {{ (window.__ssBlocked = window.__ssBlocked || []).push(n); throw new DOMException('blocked', 'SecurityError'); }}}});
}}"""
# the page can overwrite window.__ssBlocked: only our own names are read back, never its values
_DISABLED = f"() => {{ const b = window.__ssBlocked; return Array.isArray(b) ? {_FEATURES!r}.filter(n => b.includes(n)) : []; }}"
# ad-parking networks and for-sale pages: a parked typo domain shows no phishing page (yet); in one live run 35 of 59 finds were parked.
# Matched on the hosts the page loads from (not the page's own site) and on the visible text, never on raw HTML a kit could stuff with a marker.
_PARKING_HOSTS = (
    "parklogic.com",
    "sedoparking.com",
    "bodis.com",
    "parkingcrew.net",
    "above.com",
    "dan.com",
    "afternic.com",
    "hugedomains.com",
    "undeveloped.com",
    "forsale.godaddy.com",
)  # GoDaddy/Afternic for-sale redirect: it often answers a headless browser with "Access Denied" (talabat.xyz + 11 more)
_PARKED_TEXT = re.compile(
    r"(?<!\w)(is parked free|this domain (?:name )?(?:is |may be )?for sale|buy this domain)(?!\w)", re.IGNORECASE
)
_WEBHOOK_HOSTS = (
    "discord.com",
    "discordapp.com",
)  # only webhook paths (also versioned /api/v10/webhooks/): the rest of Discord is an ordinary site
_WEBHOOK_PATH = re.compile(r"^/api(/v\d+)?/webhooks/")
_STARTED = time.monotonic()  # the parent's kill clock starts with this process, not with the browser


def _host(parts) -> str:
    return (parts.hostname or "").lower().rstrip(".")  # "api.telegram.org." is the same host


def _under(host: str, domains) -> str | None:
    return next((d for d in domains if host == d or host.endswith("." + d)), None)


def exfil_host(parts, exfil_hosts) -> str | None:
    host = _host(parts)
    if _WEBHOOK_PATH.match(parts.path) and _under(host, _WEBHOOK_HOSTS):
        return host
    return host if _under(host, exfil_hosts) else None


def parked_marker(final_host: str, loaded_hosts: set[str], text: str) -> str | None:
    own = registrable_of(final_host) if final_host else ""
    for host in sorted(loaded_hosts):
        for park in _PARKING_HOSTS:
            if (host == park or host.endswith("." + park)) and own != park:
                return park
    found = _PARKED_TEXT.search(text)
    return found.group(1).lower() if found else None


_FIELDS = """() => [...document.querySelectorAll('input, textarea, select')].filter(e => !['hidden', 'submit', 'button', 'image', 'reset', 'checkbox', 'radio'].includes((e.type || '').toLowerCase())).slice(0, 60)
  .map(e => ({name: e.name || e.id || '', type: (e.type || e.tagName).toLowerCase(), autocomplete: e.autocomplete || '',
              label: ((e.labels && e.labels[0] && e.labels[0].innerText) || e.getAttribute('aria-label') || e.placeholder || '').trim().slice(0, 80)}))"""
_LOGO = """() => { const seen = e => { const r = e.getBoundingClientRect(); return r.width >= 24 && r.height >= 12 && r.bottom > 0 && getComputedStyle(e).visibility !== 'hidden'; };
  const generic = i => /app.?store|google.?play|play.?store|app.?gallery|badge|facebook|twitter|instagram|linkedin|youtube|whatsapp|tiktok|mastercard/i.test(i.src + ' ' + i.alt + ' ' + i.className);
  const imgs = [...document.images].filter(i => seen(i) && !generic(i));
  const el = imgs.find(i => /logo/i.test(i.src + ' ' + i.alt + ' ' + i.className + ' ' + i.id)) || imgs.find(i => i.getBoundingClientRect().top < 200);
  if (el) el.setAttribute('data-ss-logo', '1'); return !!el; }"""
_FAVICON = """async () => { const l = document.querySelector('link[rel~="icon"]'); const url = new URL(l ? l.getAttribute('href') : '/favicon.ico', document.baseURI);
  if (url.origin !== location.origin) return null;
  try { const r = await fetch(url, {credentials: 'omit'}); if (!r.ok) return null; const b = new Uint8Array(await r.arrayBuffer());
    return b.length > 200000 ? null : btoa(String.fromCharCode(...b)); } catch (e) { return null; } }"""
_DHASH = """async (b64) => { const img = new Image(); img.src = 'data:image/png;base64,' + b64; await img.decode();
  const c = document.createElement('canvas'); c.width = 9; c.height = 8; const x = c.getContext('2d', {willReadFrequently: true}); x.drawImage(img, 0, 0, 9, 8);
  const d = x.getImageData(0, 0, 9, 8).data; const g = (i, j) => 0.299 * d[(j * 9 + i) * 4] + 0.587 * d[(j * 9 + i) * 4 + 1] + 0.114 * d[(j * 9 + i) * 4 + 2];
  let bits = ''; for (let j = 0; j < 8; j++) for (let i = 0; i < 8; i++) bits += g(i, j) > g(i + 1, j) ? '1' : '0';
  return BigInt('0b' + bits).toString(16).padStart(16, '0'); }"""


async def _host_ok(host: str, fake_dns: dict) -> bool | None:
    """True public, False private, None does not resolve (Chromium fails that request by itself). Resolved again for every request."""
    try:
        return _is_public(str(ipaddress.ip_address(host.strip("[]"))))
    except ValueError:
        pass
    if host == "localhost" or host.endswith(".localhost"):
        return False
    if host in fake_dns:  # tests: one answer list per lookup, the last one repeats
        answers = fake_dns[host].pop(0) if len(fake_dns[host]) > 1 else fake_dns[host][0]
    else:
        try:
            answers = [
                i[4][0] for i in await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            ]
        except OSError:
            return None
    return all(_is_public(a.split("%")[0]) for a in answers)


async def run(job: dict) -> dict:
    out = Path(job["out_dir"])
    out.mkdir(parents=True, exist_ok=True)
    fake_dns = {h: [list(a) for a in answers] for h, answers in job.get("fake_dns", {}).items()}
    state = {"blocked": None, "bytes": 0, "requests": 0, "hosts": set(), "exfil": set(), "hotlinks": set()}

    too_big = f"page larger than {job['max_bytes'] // 1_000_000} MB"

    def block(reason: str) -> None:
        state["blocked"] = state["blocked"] or reason

    async with async_playwright() as pw:
        args = ["--force-webrtc-ip-handling-policy=disable_non_proxied_udp"]
        if fake_dns:  # tests only: the guard sees a public answer, Chromium really goes to the local test server
            args.append("--host-resolver-rules=" + ", ".join(f"MAP {h} 127.0.0.1" for h in fake_dns))
        browser = await pw.chromium.launch(args=args)
        try:
            context = await browser.new_context(
                user_agent=MOBILE_UA,
                viewport={"width": 390, "height": 844},
                is_mobile=True,
                has_touch=True,
                locale="en-AE",
                timezone_id="Asia/Dubai",
                accept_downloads=False,
                service_workers="block",
                permissions=[],
            )
            await context.add_init_script(_INIT)

            async def guard(route, request):
                state["requests"] += 1
                parts = urlsplit(request.url)
                state["hosts"].add(_host(parts))
                sent = exfil_host(parts, job.get("exfil_hosts", []))
                if sent:
                    state["exfil"].add(sent)  # recorded, never delivered
                    return await route.abort()
                official = _under(_host(parts), job.get("official_domains", []))
                if official and not (request.is_navigation_request() and request.frame.parent_frame is None):
                    state["hotlinks"].add(
                        official
                    )  # whether the page itself is official is decided at the end, on its final host
                hops, prior = 0, request
                while prior.redirected_from:
                    hops, prior = hops + 1, prior.redirected_from
                if (
                    state["blocked"]
                    or request.method not in ("GET", "HEAD")
                    or parts.scheme not in ("http", "https")
                    or request.resource_type == "media"
                ):  # no video / audio: heavy, not needed for a picture
                    return await route.abort()
                if state["requests"] > job["max_requests"]:
                    block("too many requests")
                elif hops > job["max_redirects"]:
                    block(f"more than {job['max_redirects']} redirects")
                else:
                    verdict = await _host_ok(parts.hostname or "", fake_dns)
                    if (
                        verdict is None
                        and request.is_navigation_request()
                        and request.frame.parent_frame is None
                        and request.redirected_from is None
                        and state["requests"] > 1
                    ):
                        return await route.fulfill(
                            status=204
                        )  # a script sends the page to a dead host: 204 keeps the page we already have instead of an error page
                    if verdict is None:
                        return await route.abort()
                    if verdict is False:
                        block("private address blocked")
                if state["blocked"]:
                    return await route.abort()
                await route.continue_()

            await context.route("**/*", guard)

            async def socket_guard(ws):
                state["requests"] += 1
                parts = urlsplit(ws.url)
                sent = exfil_host(parts, job.get("exfil_hosts", []))
                if sent:
                    state["exfil"].add(sent)
                    return await ws.close()
                verdict = (
                    None
                    if state["blocked"] or parts.scheme not in ("ws", "wss")
                    else await _host_ok(parts.hostname or "", fake_dns)
                )
                if verdict is True:
                    ws.connect_to_server()  # public host: the page keeps its live connection (no form or brand otherwise)
                    return
                if verdict is False:
                    block("private address blocked")
                await ws.close()

            await context.route_web_socket(re.compile(".*"), socket_guard)
            page = await context.new_page()
            page.on("download", lambda _: block("download blocked"))
            cdp = await context.new_cdp_session(page)
            await cdp.send("Network.enable")

            def received(event):
                state["bytes"] += event["dataLength"]
                if state["bytes"] > job["max_bytes"]:
                    block(too_big)
                    asyncio.ensure_future(cdp.send("Page.stopLoading"))  # noqa: RUF006 -- fire-and-forget: the page is being torn down

            cdp.on("Network.dataReceived", received)
            result = {
                "status": "ok",
                "reason": None,
                "final_url": None,
                "redirect_chain": [],
                "title": None,
                "visible_text": "",
                "form_fields": [],
                "screenshot_path": None,
                "html_path": None,
                "bytes_received": 0,
                "hashes": {},
                "favicon": None,
                "disabled": [],
                "parked": None,
                "exfil": [],
                "hotlinks": [],
            }
            try:
                deadline = (
                    _STARTED + job["hard_kill_s"] - 10
                )  # leave time for the picture, text, logo and hashes before the parent kills us
                response = await page.goto(job["url"], wait_until="load", timeout=job["nav_timeout_ms"])
                await page.wait_for_timeout(1500)  # scripts that draw the form after load
                chain, hop = [], response.request if response else None
                while hop:
                    chain.insert(0, hop.url)
                    hop = hop.redirected_from
                chain = chain or [job["url"]]
                for _ in range(
                    job["max_redirects"]
                ):  # cloaking redirectors probe the target first (HEAD), then location.replace() a second later
                    left_ms = int((deadline - time.monotonic()) * 1000)
                    if left_ms < 3000:
                        break
                    before = page.url
                    try:
                        await page.wait_for_url(lambda u, b=before: u != b, timeout=min(1500, left_ms - 2000))
                        await page.wait_for_load_state(
                            "load", timeout=max(int((deadline - time.monotonic()) * 1000), 1)
                        )
                    except PlaywrightError:
                        break
                    await page.wait_for_timeout(1000)
                if page.url != chain[-1] and not page.url.startswith(
                    "chrome-error:"
                ):  # script redirects, including one that finished during the first wait
                    chain.append(page.url)
                text = await page.evaluate("document.body ? document.body.innerText : ''")
                result["parked"] = parked_marker(
                    urlsplit(page.url).hostname or "", state["hosts"], f"{await page.title()}\n{text[:20000]}"
                )
                result.update(
                    final_url=page.url,
                    redirect_chain=chain,
                    title=await page.title(),
                    form_fields=await page.evaluate(_FIELDS),
                    visible_text=text[:20000],
                )
                disabled = set()
                for frame in page.frames:  # every frame has its own marker (an iframe's Worker is refused there)
                    try:
                        disabled.update(await frame.evaluate(_DISABLED))
                    except PlaywrightError:
                        pass  # frame went away
                result["disabled"] = sorted(disabled)
                png = await page.screenshot(type="png")
                (out / "screenshot.png").write_bytes(png)
                result["screenshot_path"] = str(out / "screenshot.png")
                result["favicon"] = await page.evaluate(_FAVICON) if not state["blocked"] else None
                logo = None
                if await page.evaluate(_LOGO):
                    logo = await page.locator("[data-ss-logo]").first.screenshot(timeout=3000)
                hasher = await browser.new_page()  # no network: only data: images
                result["hashes"] = {
                    "page": await hasher.evaluate(_DHASH, base64.b64encode(png).decode()),
                    "logo": await hasher.evaluate(_DHASH, base64.b64encode(logo).decode()) if logo else None,
                }
            except PlaywrightError as exc:
                if "Download is starting" in str(exc):
                    block("download blocked")
                if not state["blocked"]:
                    result.update(
                        status="timeout" if "Timeout" in str(exc) else "error", reason=str(exc).splitlines()[0][:200]
                    )
            if state["bytes"] > job["max_bytes"]:
                block(too_big)
            result["bytes_received"] = state["bytes"]
            final = urlsplit(result["final_url"] or job["url"])
            own = _under(_host(final), job.get("official_domains", []))
            result.update(
                exfil=sorted(state["exfil"]), hotlinks=sorted(h for h in state["hotlinks"] if h != own)
            )  # an official page loading its own assets is no hotlink
            if state["blocked"]:
                result.update(status="blocked", reason=state["blocked"])
            return result
        finally:
            await browser.close()


if __name__ == "__main__":
    try:
        outcome = asyncio.run(run(json.loads(sys.stdin.read())))
    except Exception as exc:  # noqa: BLE001 - the parent must always get a result line
        outcome = {"status": "error", "reason": f"{type(exc).__name__}: {exc}"[:200]}
    print(json.dumps(outcome))
