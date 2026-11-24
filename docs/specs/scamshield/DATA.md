# DATA: ScamShield (v1)
Revision 2. Exact types and yaml schemas: `CONTRACTS.md`. Schema lives in `scamshield/schema.sql`; this file is its meaning.

## Rules for every stored fact
- **Provenance on every fact:** `source` (name from `sources`), `observed_at` (when the source says it was true /
  first seen; NULL if the source does not say), `fetched_at` (when we got it), `data_mode` (LIVE | DEMO | SYNTHETIC),
  `raw_ref` (path/sha256 of the raw response when kept). A fact without source + fetched_at is a bug.
- **LIVE** = fetched by this running system. **DEMO** = real data collected earlier (fixtures), replayed with its
  original timestamps. **SYNTHETIC** = invented, tests only; never shown in the demo DB. Badge on every row in UI.
- Facts are append-only. A newer answer is a new row; the card shows the latest per type + "history".
- Missing is explicit: `status=missing` (source answered "no data") vs `status=error` (source failed). Neither is
  ever replaced by a guess. Unknown domain age ≠ new domain.
  For coverage, `missing` counts as a completed check (the source answered); `error` does not.
- **Evidence ID** = `facts.id`, assigned only by `db.insert_facts`; shown as `E<id>`.

## Tables (SQLite, one file `data/scamshield.db`)
| Table | Key fields | Notes |
|---|---|---|
| sources | name PK, kind (enrich/connector/llm), data_mode, enabled, status (ok/degraded/down/not_configured), last_success_at, last_error, last_error_at, calls_today | drives source status strip |
| domains | id, fqdn UNIQUE, registrable, brand_id, first_seen_at, found_by (source name or `baseline` or `manual`), last_seen_at, state, risk_score, coverage, last_assessed_at, data_mode | fqdn lower-case IDNA (punycode); badge rule in CONTRACTS.md |
| urls | id, domain_id, url (normalized, query kept), first_seen_at, source, data_mode | UNIQUE(url) |
| facts | id (= evidence ID), domain_id, type, value_json, source, observed_at, fetched_at, status, error, data_mode, raw_ref, job_id (job that wrote it; NULL for intake evidence; a re-run replaces that job's facts) | index (domain_id, type, fetched_at), (job_id) |
| feed_index | domain PK, sources (csv), first_listed_at, last_listed_at | full feed lists for lookups; rebuilt every 6 h into `feed_index_new`, then swapped in one transaction |
| feed_meta | key PK, value | `baseline_done_at`, last refresh per feed |
| jobs | id, kind, class (light/browser), target, payload_json, priority, status (queued/running/done/failed/partial), attempts, max_attempts, run_after, started_at, finished_at, error, idem_key UNIQUE, created_at (ingest time, UTC; NULL on jobs from before live mode) | kinds, payloads, buckets: CONTRACTS.md |
| heartbeats | id, at, loop (`boot`, `pause`, `worker`, `feeds`, `ct:<log>`), ok, entries, tree_size, skipped, candidates, lag_s, error | live mode proof that a loop ran; `pause` row: lag_s = seconds the process did not beat |
| cursors | connector PK, cursor, updated_at | survive restart; ct_tiled: `{log_url: next_index}` per log |
| assessments | id, domain_id, rule_version, risk_score, coverage, state, flags_json, components_json, evidence_ids_json, created_at | history, never updated |
| edges | id, a_domain_id, b_domain_id, feature, shared_value, rarity, strength, sentence, evidence_ids_json, first_seen_at, last_seen_at, rule_version | UNIQUE(a,b,feature,shared_value), a<b |
| artifacts | id, domain_id, kind (screenshot/html_gz/visible_text/redirect_chain), path, sha256, bytes, captured_at, data_mode | files in `data/evidence/` named by sha256 |
| explanations | id, domain_id, assessment_id, model, prompt_version, output_json, valid, error, input_tokens, output_tokens, trigger (manual_check/auto_top/click), created_at | one valid row per assessment max |
| llm_spend | (day, role) PK, calls, input_tokens, output_tokens, est_usd | simple counter for the $15/day cap; one row per role (explain, judge) |
| ai_reviews | id, domain_id, assessment_id, role (judge), model, prompt_version, output_json (verdict, E-ids), valid, error, input_tokens, output_tokens, est_usd, created_at; unique (assessment_id, role) = once per assessment | AI sorts and labels inside GRAY, never hides or decides; "AI check: not run (…)" when absent |
| budgets | source, pool (manual/auto), window_start, used | per-source request budgets (CertSpotter 60/h = 40 manual + 20 auto, Tavily 40/day, ...); PK (source, pool, window_start) |
| search_runs | id, query, connector, run_at, status, result_count, error | |
| search_results | id, run_id, rank, url, domain_id, is_official, title, fetched_at, data_mode | also the 24 h cache; title/snippet untrusted |
| feedback | id, domain_id, assessment_id, verdict (scam/legit/unclear), reason (required), analyst (optional, defaults to the maintainer), created_at | append-only |

## Fact catalogue
| Fact type | Source | Availability | Rule / edge cases | Shown as | To LLM |
|---|---|---|---|---|---|
| dns_a / aaaa / cname / ns / mx | dnspython, system resolver | usually; NXDOMAIN common for dead phish | NXDOMAIN → status=missing "domain does not resolve"; timeout → error | list of records + TTL | yes |
| ip_asn | Team Cymru DNS (origin.asn.cymru.com) | usually | per IP; no answer → missing | "AS22612 Namecheap" | yes |
| created_at / registrar / expires_at | RDAP (IANA bootstrap) | often missing; .ae RDAP fails, .ae WHOIS cut from v1 | missing → "Registration date unknown" (not risk); store dates + registrar only, **no registrant contacts** | date + age in days | yes |
| certs | CertSpotter API (issuances for this exact domain + subdomains; enrichment only, not discovery) | usually; budget 60/h | first/last issuance, issuer, SAN names; cert present ≠ legit | first cert date, issuer | yes |
| in_feed | feed_index (Phishing.Database, phishing.army, OpenPhish) | yes when listed | match on fqdn or registrable; record which feed + first_listed_at; listing date ≠ attack date | "Listed in OpenPhish since …" | yes |
| lookalike | computed from brands.yaml over **every FQDN label** | always | brand, keyword, label hit, method (token/homoglyph/idn/edit-distance), position (registrable/subdomain/platform_label), restricted_zone, context (name/url_path/none), mode (ct/feed), official domain imitated, score; exclusions; *.gov.ae → ×0.2 + GOV_AE | "Imitates Aramex (aramex.com): token 'aramex' in label 1" | yes |
| official | brands.yaml allowlist | always | exact registrable match → OFFICIAL | green "Official domain" | yes |
| redirect_chain | snapshot (browser guard) | when site reachable | ≤ 5 hops, each hop checked | list of URLs | yes |
| snapshot_* (title, visible_text, form_fields, screenshot) | sandboxed browser | layer 5, analyst click only | form fields = names/types/labels only, never values | PNG + field list | title, form fields, ≤ 4 KB text as untrusted |
| ct_entry | ct_tiled (LE Willow/Sycamore) | only for brand matches | log, index, precert/cert, leaf timestamp (= observed_at), issuer, matched SAN, brand + method; non-matching names never stored | "Seen in CT log Willow (precert) at HH:MM" | yes |
| search_hit | Tavily keyless (fallbacks: Tavily key, Serper.dev, SerpAPI) | when within budget | rank, query, country, run time; cached 24 h | row in Search monitor | no |
| edge facts | graph.py from ip/asn/ns/name_template facts | derived | stored in `edges` with both sides' evidence IDs | sentence on graph edge | yes |

Derived values (computed in ONE place each): risk/coverage/state → `scoring.py`; edges, rarity → `graph.py`;
brand match → `enrich/lookalike.py`. Weights and thresholds → `config/scoring.yaml`.

## Reference data (config, versioned in git)
- `config/brands.yaml`: brand name, official registrable domains, keywords, exclusion words, search queries.
  Initial brands: (RTA, Salik, Abu Dhabi Police, Dubai Police, TAMM, Emirates Post, Aramex, banks, telcos).
  Default: the list is compiled from official sites and reviewed by a maintainer; each entry has verified_by/at.
- `config/shared_infra.yaml`: CDN/big-hosting ASNs, NS suffixes, IP ranges treated as shared (rarity cap).
- Demo cases (data_mode=DEMO) are real saved cases replayed with their original timestamps; they are not shipped in this repository.

## Retention (local laptop, v1)
- No automatic deletion in v1 (eviction, purge jobs and `--reset-demo` are cut). Expected DB < 500 MB,
  evidence < 1 GB for the event. Manual reset = stop app, move `data/` aside.
- feed_index: replaced on each refresh (current listings; `first_listed_at` carried over).
- Raw source responses: kept only for facts that are shown (raw_ref), max 2 MB each.

## Personal data
- **Analyst name (optional) and free-text reasons** in `feedback` — the only intended personal data. Stays local; never sent
  to the LLM or any external service.
- **Registrant contacts** from RDAP/WHOIS (name, email, phone, address): not stored, not shown — only dates and
  registrar. Raw WHOIS text is not kept.
- Screenshots/visible text of scam pages could contain third-party data (e.g. a fake "victim" form pre-filled) —
  rare; stored locally only, never published. Page text sent to the LLM is limited to 4 KB.
- Sent to Anthropic: domain facts, assessment, edges, snapshot title/form structure/≤ 4 KB text. Nothing else.
- Sent to Tavily/search fallbacks: only the fixed queries from brands.yaml.
