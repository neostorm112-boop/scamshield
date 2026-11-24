# ADR 0004: Screenshots with Playwright Chromium in a killable subprocess, behind SSRF checks
Date: 2026-11-19 · Status: accepted

## Context
Requirement: the analyst sees a screenshot, never the live site; no form input; isolated browser. User-entered URLs must not
reach private/local networks (SSRF).

## Decision
- `netsafe` is the only way to fetch a suspect URL: normalize, resolve, reject private/loopback/link-local/
  multicast/reserved/CGNAT (v4+v6) and `localhost`, only ports 80/443. httpx connects by hostname (keeps SNI and
  certificate checks valid — connecting to a raw IP would break TLS), then the actual peer IP is verified before the
  body is read; private peer → abort. Body streamed with a 10 MB cap. Redirects manual (max 5), each hop re-checked.
- `snapshot_runner` runs as a subprocess per job (hard kill at 25 s): fresh Chromium context, downloads off,
  service workers blocked, no permissions, WebSocket/WebRTC disabled (init script + closed WS routes + Chromium
  WebRTC policy flag), every request intercepted → host resolved → private targets and non-GET aborted, byte
  counter aborts at 10 MB / 150 requests; 15 s navigation timeout; no clicks or typing. Max one browser at a time.
- Snapshots run when the analyst clicks (the request waits up to 25 s) and, automatically for queued GRAY / GRAY_LOW domains that resolve: one at a time, `sources.yaml snapshot.budget_per_hour` (20), never for a domain that was already snapshotted or decided.
- Stored HTML is never served as HTML (gzip, `text/plain` download, CSP `default-src 'none'`). UI shows only the
  PNG and escaped visible text.

## Why
Playwright is the most reliable scripted headless browser on macOS ARM with Python bindings; subprocess isolation
contains crashes and memory. A full VM/container sandbox costs RAM and setup time we do not have.

## Consequences / residual risk
The peer-IP check in `netsafe` runs after the TCP/TLS connection is made and the request is sent (httpx gives
the peer address only then), so one GET could reach a private address before we abort and discard the response.
Accepted for a local laptop demo (GET only, no body sent, response discarded).
DNS rebinding between check and fetch is reduced (per-request re-check) but not eliminated; acceptable for a local,
non-networked-admin laptop demo. Not acceptable for a server deployment — revisit with an egress proxy then.

## Implementation notes (2026-11-20)
- Playwright `1.56.0` is pinned because its browser build is Chromium 1194 (the build in the local cache). No Pillow: the perceptual hash (64-bit dHash of the page picture and of the logo element) is computed by Chromium itself from the PNG.
- The browser guard (route handler per request, per redirect hop) does the redirect / private-address / size checks; `netsafe.check_url` runs on the start URL; `netsafe.safe_get` was removed as dead code (never called; the browser guard replaced it); the favicon is read inside the page (same origin only, through the same guard). The page is not fetched twice.
- Brand shown on a page: name (title / text), logo hash and page hash against `config/brand_refs.json` (built only from the official domains by `python -m scamshield.tools.build_brand_refs`), favicon sha256. A page-picture match alone is dropped: two mostly white pages look alike.
- Residual risk unchanged: the resolver check and Chromium's own lookup are two lookups (DNS rebinding reduced, not removed).

## Update 2026-11-20
- WebSocket: a page-level socket to a **public** host is allowed (real kits use socket.io; blocking every socket stopped the snapshot before the form was drawn); to a private / local host → "private address blocked". WebRTC, Worker, SharedWorker stay disabled (the constructor throws); an attempt no longer stops the snapshot — dubaipolice.gov.ae, dm.gov.ae, citibank.com use workers — it is recorded on the page fact as evidence.
- Reference build keeps a domain's previous entry when the site fails this time or loses its logo (official sites are flaky behind bot walls).
- Size stop raised from 10 MB to 40 MB (`sources.yaml snapshot.max_bytes`): rta.ae is > 10 MB. Official reference build: 60 MB / 800 requests, retry on `www.`.
- **Accepted risk — DNS rebinding:** the guard resolves the host itself, Chromium resolves it again. A host that answers public to us and private to Chromium a moment later can reach one private address with a GET (no body, no clicks, response not stored past the page). Accepted for the local laptop demo and hackathon; a server deployment needs an egress proxy that pins the resolved IP.
- **Accepted risk — public WebSocket:** a socket to a public host is proxied by the Playwright driver; its bytes are not in the size counter and the page can send data out through it for up to `hard_kill_s` (25 s). The host was already reachable by GET, so nothing private is opened; the driver resolves the name again (same rebinding risk as above). Accepted for the demo; the egress proxy fixes both for a server.
- The page cannot feed text into our evidence: of `window.__ssBlocked` only our own five feature names are read back.
- After the first live run: HEAD is allowed like GET (no body; cloaking redirectors probe the target with HEAD before `location.replace`); script redirects after load are followed within the 25 s kill (deadline = hard_kill_s − 7 s), each new URL appended to the redirect chain; broken HTTPS (ERR_SSL / ERR_CERT / connection closed, refused or reset) is retried once over plain http. Parking pages (parklogic, Sedo, Bodis, GoDaddy "parked free", for-sale) are marked `parked` on the page fact; a parked GRAY domain with no form drops to GRAY_LOW ("snapshot again later").

## Change 2026-11-22 (parallel automatic snapshots)
- Why: the product scenario needs ~120 snapshots an hour; one browser at a time with a 25 s kill caps out near 20-60 an hour in practice, and the queue grew faster than it drained.
- Decision: up to `snapshot.concurrency` (3) automatic snapshots run at once, **each in its own runner subprocess with its own Chromium process and fresh context**, exactly as before. One Chromium with N contexts was rejected: contexts share the browser process and one crash, hang or renderer exploit would hit all N pages, and the hard kill (whole process group) could no longer stop one snapshot without killing the others. Isolation per snapshot is unchanged.
- "One browser at a time" now reads: at most `concurrency` automatic browsers plus one for the analyst's click (separate slot, never queued behind automatic ones), so `concurrency + 1` in total. Budget `budget_per_hour` 20 -> 120.
- The monitor claims domains one at a time (priority unchanged: UAE brand hits, due re-snapshots, then generic names; a domain being snapshotted is skipped), so one domain is never taken twice at once. Facts are written after the browser exits, in short transactions.
- Memory is limited only by the browser count and the kill timer; the free-disk check (`min_free_gb`) is applied before every launch, automatic ones included.
