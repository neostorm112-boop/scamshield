# ADR 0006: Discovery = CT tiled logs + feed diffs + Tavily search, behind one connector contract
Date: 2026-11-19 (rev. 3, CT spike done) · Status: accepted

## Decision
Every discovery source implements `fetch(cursor, since, limit, ctx) -> CandidateBatch` (CONTRACTS.md) in one file
under `connectors/`, configured in `config/sources.yaml`; cursor persisted in `cursors`.
- `ct_tiled`: direct reading of 2 Let's Encrypt static-ct (tiled) logs, Willow and Sycamore 2026h2 (from gstatic
  `log_list v3` `tiled_logs`): `/checkpoint` every ~2 s, `/tile/data/...`, precert + cert leaves parsed with
  `cryptography`, wildcards stripped, 403 partial tiles retried, 429 backoff. One long-lived loop per log; only
  brand matches are stored. Free, no key, ~40 MB RAM per log (FEASIBILITY.md).
- `feeds`: Phishing.Database, phishing.army, OpenPhish every 6 h; **diffs** become candidates; first run = baseline.
- `tavily_search`: Tavily keyless (`X-Tavily-Access-Mode: keyless`, `country`), 24 h cache, 40 queries/day, demo
  queries pre-warmed. Fallbacks, same contract: Tavily free key → Serper.dev (`gl=ae`) → SerpAPI. Rejected: Google
  CSE, Bing API (closed), DuckDuckGo (no API), Brave (card required).
- `demo_fixture`: saved real cases replayed as DEMO.
- CertSpotter is enrichment only (exact domains); crt.sh and certstream are not used (flaky / dead).

## Why
CT precerts are the earliest public signal of a new HTTPS phishing site and the tiled API is free. The UAE hit rate
is unknown, so feed diffs and search run alongside. One contract keeps each source swappable in under an hour.

## Consequences
- New dependency `cryptography`. Only Let's Encrypt logs → certs from other CAs are missed.
- Log URLs rotate by half-year shard (2026h2 → 2027h1): update `sources.yaml` from log_list v3.
