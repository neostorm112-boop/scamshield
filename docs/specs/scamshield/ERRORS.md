# ERRORS: ScamShield (v1)
Revision 2. These rows are also acceptance criteria for failure handling (see bottom).
Principle: a failing source never stops a check or the monitor; the card says what was not checked and why.
Nothing is ever filled with a guess. All texts below are the exact UI wording (English).

## Failure scenarios
| If… | Analyst sees | LLM spend | Retry | Alert |
|---|---|---|---|---|
| Enrichment source down / timeout (DNS server, Team Cymru, RDAP, CertSpotter) | Card row: "Not checked: <source> — no answer (timeout 8 s). Coverage reduced." Coverage shows e.g. "Checks completed 4/5" (5 checks: DNS, ASN, registration date, certificates, phishing feeds). | none | 2 retries, backoff 2 s → 8 s, jitter; then job `partial` | source strip turns amber; red after 3 failed calls in a row |
| Source rate-limited (HTTP 429 / quota) | "Not checked: <source> — rate limit reached, will retry after HH:MM." | none | wait `Retry-After` (or 15 min); source paused till then | strip amber "rate-limited until HH:MM" |
| Connector not configured (search fallback without key) | Strip: "<source>: not configured" (grey). | none | none | grey badge, no alarm |
| Search provider fails or keyless limit hit (Tavily) | Search monitor: "Tavily: <limit reached / no answer>. Switched to <fallback>." If all fail: "Search unavailable — showing results cached at HH:MM" (each row keeps its own fetched time; DEMO rows badged DEMO). | none | next fallback in `sources.yaml` order; retry Tavily next cycle | strip amber |
| Own request budget used up (CertSpotter 60/h, Tavily 40/day) | "Not checked: <source> — hourly/daily request budget used, will retry after HH:MM." | none | job re-queued after window | strip amber "budget" |
| CT log: partial tile 403 / 429 / log unreachable | Strip: "CT <log>: catching up" / "rate-limited, retrying in N s" / "unreachable since HH:MM". Feed keeps working from other sources. | none | 403 → next poll; 429 / errors → backoff 2 s → 60 s | amber; red after 10 min down |
| CT lag > 1 h after restart/outage | Strip: "CT <log>: skipped entries <a>–<b> (≈ HH:MM–HH:MM) to catch up". Never shown as "nothing found". | none | — | amber, logged |
| Feed download fails (GitHub raw / OpenPhish) | Strip: "<feed>: last update HH:MM (stale)". Card row "Phishing feeds: checked against list from <time>". | none | next scheduled run (6 h), one retry after 10 min | amber when older than 12 h |
| LLM down / timeout / invalid JSON / unknown evidence ID | Card: "AI explanation unavailable (<reason>). Risk and evidence above are not affected." Button "Try again". | failed call logged with tokens if any | 1 automatic retry on invalid output; no loop | none (explanations are optional) |
| LLM daily spend cap reached ($15) | "AI explanation paused: daily budget ($15) reached. Resets at 00:00." | stops | next day | strip "AI: budget reached" |
| Auto-explain daily quota used (20 discovered domains) | Card: "AI explanation not generated automatically today — press Explain." | none until click | — | none |
| DNS NXDOMAIN (domain does not exist) | "Domain does not resolve (NXDOMAIN) at HH:MM — site may be down or not yet live." Score uses other signals; snapshot skipped. | none | re-check in 6 h (monitor), max 4 times | none |
| DNS SERVFAIL / resolver error | "Not checked: DNS — resolver error." | none | 2 retries | amber if repeated |
| Unknown domain age (RDAP not found, .ae, privacy) | "Registration date: unknown (RDAP had no record)". Age does not raise risk; counts as a completed check. | none | none (.ae WHOIS not implemented) | none |
| Browser timeout / crash (snapshot) | "Snapshot not taken: page did not load in 15 s." Card keeps all other facts. | none | none automatic; analyst can press Snapshot again | none |
| Malicious page behaviour (download, redirect or sub-request to a private IP, DNS rebinding, WebSocket to a private address, > 5 redirects, > 40 MB (`sources.yaml snapshot.max_bytes`) or > 150 requests) | "Snapshot stopped for safety: <download blocked / private address blocked / live connection blocked / more than 5 redirects / page larger than 40 MB / too many requests>." A WebSocket to a public host is allowed (phishing kits use socket.io; blocking it lost the form and brand). WebRTC / Worker are refused by the sandbox (constructor throws) and the snapshot goes on; the attempt shows in the page fact: "…; tried Worker — refused by the sandbox". This itself is recorded as a fact (`snapshot_blocked`). | none | no retry | none |
| Parked domain (ad-parking or for-sale page) | Page fact: "Page title “…”; parked domain (ad page, “parklogic”)". A GRAY domain with no form drops to GRAY_LOW: "Parked domain (ad page), no phishing page yet — snapshot again later". | none | none automatic (no daily re-snapshot of parked domains) | none |
| Prompt injection text in page | Nothing special: text is shown escaped as evidence; explanation is validated. If the model output fails validation: "AI explanation unavailable (output rejected)". | logged | no | none |
| Bad URL input (empty, not a URL, javascript:, file:, mailto:) | Under the box: "This is not a web link. Paste a link starting with http(s):// or a domain like example.com." | none | — | — |
| URL points to private/loopback/link-local/reserved IP or `localhost` | "Blocked: this link points to a private or local network address. Only public internet sites can be checked." | none | — | logged |
| URL with credentials (`user:pass@`) or non-standard port | Credentials stripped and noted ("link contained a login part, removed"); ports other than 80/443 → "Only ports 80 and 443 are checked." | none | — | — |
| Official domain entered | Card: green "Official domain of <brand> (from verified list)". Risk not computed as high. | none | — | — |
| App restarted mid-check | Card shows "Check resumed after restart" next to the job; running jobs re-queued. | none | automatic | none |
| Disk almost full (< 1 GB free) | "Snapshot not saved: disk almost full." | none | — | strip red "storage" |
| First feed download (baseline) | Feed "New" tab: "Monitor started HH:MM. Existing feed entries loaded as baseline (see All); New shows only domains that appear after this." | none | — | none |
| AI judge cannot run (no API key, daily AI budget reached, model declined, output invalid, timeout) | Under the gray row: "AI check: not run (<no API key \| daily AI budget reached \| model declined \| output rejected \| timed out>)". Band and order unchanged; a judge answer `no`/`unclear` shows "AI unclear" and never moves or hides the row. | none if not run | none; next gray domain tries again | none |
| Domain filtered out as NOISE | Not in the queue; checkbox at the bottom "Show filtered out (N)" (same pattern as "Show decided", no tab). Each row: "Filtered out: <reason>" — "brand token is the registrable name in a restricted foreign zone (ac.bd)", "*.gov.ae host, brand-fit too weak", or "old established domain, weak brand-fit, no risk evidence" — and the action "Return to queue". | none | re-assessed on new evidence (1.3) | none |
| Phishing against a non-UAE brand (NEG B10, e.g. `meta-framex-24f.pages.dev`) | Stays in the queue with the label "Other brand: <brand>"; ranked by the normal rule, not hidden. | none | none | none |
| Domain in GRAY_LOW (little evidence yet) | Row sorted to the bottom: "Little evidence yet — re-checked at 24 h"; after the `recheck` job the row shows the re-check time and its new band. | none | one `recheck` at +24 h, then only event triggers | none |
| Database locked (rare, WAL) | Page shows "Busy, retrying…" and reloads. | none | busy_timeout 5 s, 3 tries | logged |

## Empty data
- Fact missing → row "Not checked" / "No data" with source and time; never hidden (DATA.md "Missing is explicit").
- Feed empty (no candidates yet) → "No new suspicious domains since <time>. Monitor is running (last cycle HH:MM)."
  Never insert fake LIVE rows; DEMO cases visible only with the DEMO badge.
- Graph with no edges → "No links found. Shared CDN addresses (e.g. Cloudflare) are not counted as links."
- Search monitor before the first run → "No search run yet. Next run HH:MM" + button Run now.
- No assessment yet → card shows "Checking… (n of m sources answered)" and polls.

## Acceptance
- [ ] Each row above has a pytest (sources mocked to fail / 429 / timeout) or a manual drill with command + output,
      recorded at the end of the stage that builds it.
- [ ] Drill: disable one source in `config/sources.yaml` during a check → card shows "Not checked: <source>",
      app keeps serving (a product requirement).
- [ ] Drill: `kill -9` the app mid-check, `./run.sh` again → job resumes, no duplicate facts.
- [ ] SSRF tests: `http://127.0.0.1`, `http://[::1]`, `http://10.0.0.1`, `http://169.254.169.254`,
      `http://localhost`, `http://100.64.0.1`, a domain resolving to 127.0.0.1, a redirect to 192.168.x, and a
      rebinding test (resolver mocked: public on check, 127.0.0.1 on fetch → peer-IP check / browser handler blocks).
- [ ] Snapshot tests on a local test page: WebSocket to a private address, response over the limit, download link
      → all blocked, analyst text as in the table; WebSocket to a public host → page read normally; `RTCPeerConnection` / Worker → refused, page read, attempt shown.
- [ ] Local test pages are reached only by injecting a test safety checker in pytest; the app has no
      setting that allows loopback.
- [ ] Budget test: 61st CertSpotter call in an hour → "budget" fact, no HTTP request made.
