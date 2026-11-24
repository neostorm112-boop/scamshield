# CONTRACTS: ScamShield (v1)
The parallel-build boundary. Becomes `scamshield/contracts.py` + `config/*.yaml` at L0 and is FROZEN after that
(change = 2-minute team call + edit here). Times are ISO-8601 UTC strings.

## Dataclasses
```python
DataMode = Literal["LIVE", "DEMO", "SYNTHETIC"]
FactStatus = Literal["ok", "missing", "error"]   # missing = source answered "no data"; error = source failed

@dataclass
class Fact:                      # returned by enrichers; has NO id yet
    type: str                    # see DATA.md fact catalogue, e.g. "dns_a", "ip_asn", "created_at", "in_feed"
    value: dict                  # JSON-serialisable; {} when status != "ok"
    source: str                  # = sources.name
    observed_at: str | None      # when the source says it was true; None if source does not say
    fetched_at: str
    status: FactStatus
    error: str | None = None     # short machine reason: "timeout", "http_429", "nxdomain", "servfail", ...
    data_mode: DataMode = "LIVE"
    raw_ref: str | None = None   # path of kept raw response, if any

@dataclass
class FactRow(Fact):             # what db returns; id IS the evidence ID shown in the UI as "E<id>"
    id: int = 0
    domain_id: int = 0
# Evidence IDs: db.insert_facts(domain_id, facts) -> list[FactRow]; facts.id (AUTOINCREMENT) is the evidence ID.
# Nothing else creates evidence IDs. Assessments/edges/explanations reference facts.id only.

@dataclass
class Claim:   claim: str; evidence_ids: list[int]
@dataclass
class Explanation:
    summary: str; supporting: list[Claim]; counter: list[Claim]
    uncertainties: list[str]; recommended_next_checks: list[str]; cannot_determine: bool
@dataclass
class ExplainError:  reason: Literal["timeout","api_error","invalid_json","unknown_evidence_id","budget","disabled"]; detail: str

@dataclass
class Candidate:
    value: str                   # URL or bare domain, as found
    source: str; observed_at: str | None; data_mode: DataMode
    metadata: dict               # search: {query, rank, title}; feeds: {feed}; ct_tiled: {log, index, entry_type: "precert"|"cert", issuer, not_before, brand, method}
@dataclass
class CandidateBatch:  candidates: list[Candidate]; next_cursor: str | None; status: Literal["ok","error","not_configured"]; error: str | None = None

@dataclass
class Edge:                      # contract uses fqdn; db layer maps to domain ids and stores a_id < b_id
    a: str; b: str; feature: Literal["ip","asn","ns","name_template","registrar","script","script_3p","panel"]   # script = same own script/style SHA-256 (script_3p: served by another host, medium at most), panel = same WebSocket host (urlscan, find relatives)
    shared_value: str; rarity: float; strength: float; sentence: str; evidence_ids: list[int]

@dataclass
class Assessment:
    risk_score: float            # 0..1, shown as 0–100
    coverage: float              # 0..1, shown as "Checks completed x/y"
    checks_done: int; checks_total: int
    state: Literal["OFFICIAL","ANALYST_SCAM","ANALYST_LEGIT","REVIEW_HIGH","REVIEW","NOISE","NEED_MORE_DATA"]   # NOISE = hidden obvious junk (checkbox "Show filtered out (N)"); MONITOR retired
    flags: list[str]             # IN_FEED, OFFICIAL_DOMAIN, GOV_AE, SIMILAR_TO_CONFIRMED:<fqdn>, NXDOMAIN, GRAY, GRAY_LOW, GUARD:<G>, NEG:<B>, COMPROMISED_HOST
    components: dict             # points per signal: {"B1": {"points":3,"evidence_ids":[..]}, "R1": {...}, ...}; unknown = 0 points
    evidence_ids: list[int]; rule_version: str

@dataclass
class Verdict:  verdict: Literal["scam","legit","unclear"]; reason: str; analyst: str | None; created_at: str

@dataclass
class NormalizedURL:
    raw: str; url: str           # normalized; query kept as-is
    scheme: Literal["http","https"]; host: str  # lower-case IDNA/punycode
    port: int; fqdn: str; registrable: str      # registrable via tldextract incl. PSL private suffixes
    notes: list[str]             # e.g. "credentials removed", "scheme added (https)"
@dataclass
class Rejection:
    code: Literal["NOT_A_URL","BAD_SCHEME","BAD_PORT","PRIVATE_ADDRESS","LOCALHOST","UNRESOLVABLE"]; message: str  # exact UI text, ERRORS.md

@dataclass
class SnapshotResult:
    status: Literal["ok","timeout","blocked","error"]; reason: str | None
    final_url: str | None; redirect_chain: list[str]; title: str | None; visible_text: str  # ≤ 20 KB
    form_fields: list[dict]      # [{"name","type","label"}] — structure only, never values
    screenshot_path: str | None; html_path: str | None; bytes_received: int
    hashes: dict = {}            # {"page": dHash hex, "logo": dHash hex | None, "favicon": sha256 hex | None}; form_fields items also carry "autocomplete"
    disabled: list[str] = []     # WebRTC / Worker the page tried; refused by the sandbox (only our own feature names are read back)
    parked: str | None = None    # parking / for-sale marker found in the page HTML or final URL ("parklogic", "is parked free"…)
    exfil: list[str] = []        # exfiltration-channel hosts the page contacted (api.telegram.org…); aborted, only recorded
    hotlinks: list[str] = []     # official brand domains the page loaded files from (page itself is not official)

@dataclass
class Settings:                  # config.load() -> Settings; read-only after start
    brands: list[Brand]          # parsed brands.yaml (id, name, official_domains, keywords, exclude_tokens, search_queries, verified_by, verified_at)
    sources: dict[str, SourceCfg]   # parsed sources.yaml: kind, enabled, timeout_s, budget_per_hour, budget_per_day, data_mode, key_env, extra: dict
    scoring: dict                # parsed scoring.yaml as-is
    shared_infra: dict           # {asns: [int], ns_suffixes: [str], cidrs: [str]}
    data_dir: str                # env SCAMSHIELD_DATA_DIR, default "data"
    port: int                    # env PORT, default 8000
    db_path: str; evidence_dir: str          # derived: <data_dir>/scamshield.db, <data_dir>/evidence
    secrets: dict[str, str]      # env values by NAME; never logged or rendered

class Budget:                    # backed by the `budgets` table; windows hour/day in UTC
    async def take(self, source: str, pool: Literal["manual","auto"] = "auto") -> bool   # False → caller returns error "budget"
    async def remaining(self, source: str) -> dict           # {"manual": n, "auto": n, "resets_at": iso}

@dataclass
class Ctx:                       # passed to every enricher/connector
    settings: Settings           # parsed config + env
    http: httpx.AsyncClient      # for third-party APIs (RDAP, CertSpotter, feeds, Tavily); NOT for suspect sites
    resolver: dns.asyncresolver.Resolver
    budget: Budget               # await ctx.budget.take("certspotter", pool) -> bool (False = over budget, return error "budget")
    pool: Literal["manual","auto"]  # manual checks use the reserved share of budgets
    now: Callable[[], str]
```

## Function signatures (none of them raise to the caller; failures come back as data)
```
enrich.<name>.run(fqdn: str, ctx: Ctx) -> list[Fact]                 # async; names: dns, asn, rdap, certspotter, feed_match, lookalike
connectors.<name>.fetch(cursor: str|None, since: str|None, limit: int, ctx: Ctx) -> CandidateBatch   # async
lookalike.match(fqdn: str, brands: Brands, mode: Literal["ct","feed"] = "ct", url_path: str | None = None) -> dict | None
                       # {"brand","official","keyword","label","score","method": token|homoglyph|idn|edit-distance,
                       #  "position": registrable|subdomain|platform_label, "restricted_zone": bool,
                       #  "context": name|url_path|none, "context_words": [..], "tokens": [..], "mode"}; checks EVERY label.
                       # mode="feed" (names already phishing-listed) relaxes the <= 3-char keyword rule; same value is the stored `lookalike` fact
scoring.assess(fqdn, facts: list[FactRow], edges: list[Edge], latest_verdict: Verdict|None,
               confirmed_neighbours: list[tuple[str, float]], brands, weights) -> Assessment     # pure
graph.edges_for(fqdn, db) -> list[Edge];   graph.subgraph(fqdn, db, hops=2, max_nodes=50) -> nx.Graph
netsafe.check_url(raw: str) -> NormalizedURL | Rejection             # async (resolves host)
snapshot.capture(url: str) -> SnapshotResult                          # async; spawns snapshot_runner subprocess
explain.explain(fqdn: str, assessment_id: int) -> Explanation | ExplainError                # async
db.run(fn, *args)  # await; executes fn(conn, *args) in a worker thread with that thread's own sqlite3 connection
```

## Jobs (`jobs.kind` → `payload_json`; idem_key = f"{kind}:{target}:{bucket}")
| kind | payload | target | bucket (dedupe window) | concurrency class |
|---|---|---|---|---|
| check_domain | {fqdn, url?, manual: bool} | fqdn | manual: current minute; auto: 6 h | light (≤ 3) |
| refresh_feeds | {} | "feeds" | 6 h | light |
| (ct_tiled loops are long-lived tasks, not jobs; each match → intake → check_domain) | | | | |
| run_connector | {name} | name | connector schedule | light |
| search_query | {query_id, query, country} | query_id | 24 h | light |
| compute_edges | {fqdn} | fqdn | 1 h | light |
| recheck | {fqdn, reason: "24h"\|"event"} | fqdn | 24 h | light |   # re-assess NOISE and GRAY_LOW; `llm_spend` is keyed by (day, role) |
| snapshot | {fqdn, url} | fqdn | 24 h | browser (1) |
| explain | {fqdn, assessment_id} | assessment_id | none (assessment_id is unique) | light |
Statuses: queued → running → done | partial | failed. max_attempts 3; backoff 2 s, 8 s, 30 s + jitter.

## `config/brands.yaml`
```yaml
- id: rta
  name: Roads and Transport Authority (Dubai)
  official_domains: [rta.ae]          # registrable domains; human-verified (verified_by, verified_at)
  verified_by: "<name>"; verified_at: "2026-11-2x"
  keywords: [rta]                     # matched as whole tokens of any FQDN label split on - . and digits
  # keywords ≤ 5 chars: whole-token only; longer: substring of normalised label or Levenshtein ≤1 (6–8) / ≤2 (≥9)
  exclude_tokens: []                  # e.g. tamm: [metamask, tammy]
  search_queries: ["pay RTA fine", "RTA fine payment Dubai"]
```
## `config/sources.yaml`
```yaml
certspotter: {kind: enrich, enabled: true, budget_per_hour: 60, reserve_manual: 40, timeout_s: 8, data_mode: LIVE}
tavily:      {kind: connector, enabled: true, mode: keyless, country: united arab emirates,
              budget_per_day: 40, cache_hours: 24, schedule_hours: 6, key_env: TAVILY_API_KEY}
ct_tiled:    {kind: connector, enabled: true, poll_seconds: 10,   # 10 in the dev copy; the 24 h proof copy sets 2 locally
              max_lag_minutes: 60, backoff_max_s: 60,
              logs: ["https://mon.willow.ct.letsencrypt.org/2026h2", "<sycamore 2026h2 monitoring URL from log_list v3>"]}
```
Every source has: kind, enabled, timeout_s (default 8), budget_per_hour|budget_per_day (optional), data_mode,
key_env (optional, env var NAME only).

## `config/scoring.yaml` — starting values (not truths; tuned on the 10+10 test set during practice)
```yaml
rule_version: v1
alpha: {lookalike: 0.35, feed: 0.30, age: 0.15, infra: 0.20, content: 0.20}   # content available only after a snapshot
beta:  {dns: 2, asn: 1, age: 1, certs: 1, feed: 2}     # coverage: status ok OR missing = done; error = not done
age_days_young: 30          # S_age = 1 if age ≤ 30 d, linear to 0 at 365 d; unknown → available=false
gov_ae_lookalike_factor: 0.2   # *.gov.ae (restricted registration) not in allowlist: S_lookalike × 0.2, flag GOV_AE
thresholds: {min_coverage: 0.4, monitor_below: 0.3, review_high_from: 0.7}
edge: {w: {ip: 0.5, asn: 0.2, ns: 0.4, name_template: 0.6}, group_max: [[ip, asn]], min_strength: 0.35,
       shared_rarity_cap: 0.05, similar_to_confirmed_min: 0.5}
auto: {explain_manual: true, explain_auto_per_day: 20, explain_per_domain_per_day: 1, snapshot_auto: false}
# S_infra: no edge to a scam/IN_FEED domain → available=false (excluded from S), never 0
```

## Web routes (htmx partials return HTML fragments; full pages extend `base.html`)
```
GET  /                         Feed; one view at a time: ?low=1 | ?decided=1 | ?filtered=1 | ?baseline=1, &rows=N (page)
                               GET /partials/feed-rows?since=&<view>=1&rows=N   (same view, polled every 5 s)
GET  /partials/banner          header status dot: sources + AI daily cap (polled every 10 s)
POST /check  (form: url)       → 303 to /d/{fqdn} or re-render form with Rejection.message
GET  /d/{fqdn}                 Investigation card    GET /d/{fqdn}/partials/{header|facts|explanation|snapshot|verdicts}
POST /d/{fqdn}/snapshot | /d/{fqdn}/explain | /d/{fqdn}/feedback   → return the matching partial
GET  /d/{fqdn}/graph           Graph page            GET /d/{fqdn}/graph.json  (cytoscape elements)
GET  /search                   Search monitor        POST /search/run (runs all queries now, within budget)
GET  /evidence/{artifact_id}   PNG inline; html_gz/text as text/plain attachment
```
Card polls `/d/{fqdn}/partials/facts` every 2 s while the check job is queued/running, then stops.

## Badge rule (LIVE / DEMO)
Each fact row shows its own badge. Domain badge: LIVE if it has ≥ 1 LIVE fact, else DEMO. "Found by" shows the
first discovery with its own data_mode and is never rewritten (a DEMO find stays DEMO in that column). SYNTHETIC data exists
only in test databases (`data/test-*.db`) and is never loaded into the demo DB.
