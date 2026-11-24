"""Frozen contracts (docs/specs/scamshield/CONTRACTS.md). Change only together with that file."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    import dns.asyncresolver
    import httpx

DataMode = Literal["LIVE", "DEMO", "SYNTHETIC"]
FactStatus = Literal["ok", "missing", "error"]  # missing = source answered "no data"; error = source failed


@dataclass
class Fact:  # returned by enrichers; has NO id yet
    type: str
    value: dict  # JSON-serialisable; {} when status != "ok"
    source: str
    observed_at: str | None
    fetched_at: str
    status: FactStatus
    error: str | None = None
    data_mode: DataMode = "LIVE"
    raw_ref: str | None = None


@dataclass
class FactRow(Fact):  # id IS the evidence ID shown in the UI as "E<id>"
    id: int = 0
    domain_id: int = 0


@dataclass
class Claim:
    claim: str
    evidence_ids: list[int]


@dataclass
class Explanation:
    summary: str
    supporting: list[Claim]
    counter: list[Claim]
    uncertainties: list[str]
    recommended_next_checks: list[str]
    cannot_determine: bool


@dataclass
class ExplainError:
    reason: Literal["timeout", "api_error", "invalid_json", "unknown_evidence_id", "budget", "disabled"]
    detail: str


@dataclass
class Candidate:
    value: str  # URL or bare domain, as found
    source: str
    observed_at: str | None
    data_mode: DataMode
    metadata: dict


@dataclass
class CandidateBatch:
    candidates: list[Candidate]
    next_cursor: str | None
    status: Literal["ok", "error", "not_configured"]
    error: str | None = None


@dataclass
class Edge:  # contract uses fqdn; db layer maps to domain ids and stores a_id < b_id
    a: str
    b: str
    feature: Literal[
        "ip", "asn", "ns", "name_template", "registrar", "script", "script_3p", "panel"
    ]  # script / script_3p / panel: find relatives (urlscan)
    shared_value: str
    rarity: float
    strength: float
    sentence: str
    evidence_ids: list[int]
    level: Literal["weak", "medium", "strong"] = "medium"


@dataclass
class Assessment:
    risk_score: float  # 0..1, shown as 0-100
    coverage: float  # 0..1
    checks_done: int
    checks_total: int
    state: Literal["OFFICIAL", "ANALYST_SCAM", "ANALYST_LEGIT", "REVIEW_HIGH", "REVIEW", "NOISE", "NEED_MORE_DATA"]
    flags: list[str]
    components: dict
    evidence_ids: list[int]
    rule_version: str


@dataclass
class Verdict:
    verdict: Literal["scam", "legit", "unclear"]
    reason: str
    analyst: str | None
    created_at: str


@dataclass
class NormalizedURL:
    raw: str
    url: str
    scheme: Literal["http", "https"]
    host: str
    port: int
    fqdn: str
    registrable: str
    notes: list[str]


@dataclass
class Rejection:
    code: Literal["NOT_A_URL", "BAD_SCHEME", "BAD_PORT", "PRIVATE_ADDRESS", "LOCALHOST", "UNRESOLVABLE"]
    message: str


@dataclass
class SnapshotResult:
    status: Literal["ok", "timeout", "blocked", "error"]
    reason: str | None
    final_url: str | None
    redirect_chain: list[str]
    title: str | None
    visible_text: str  # <= 20 KB
    form_fields: list[dict]  # structure only, never values
    screenshot_path: str | None
    html_path: str | None
    bytes_received: int
    hashes: dict = field(
        default_factory=dict
    )  # {"page": 16 hex (dHash), "logo": 16 hex | None, "favicon": sha256 hex | None}
    disabled: list[str] = field(
        default_factory=list
    )  # features the page tried and the browser refused (WebRTC, Worker): evidence, not a stop
    parked: str | None = None  # parking / for-sale marker found in the page (e.g. "parklogic"): no phishing page yet
    exfil: list[str] = field(
        default_factory=list
    )  # exfiltration-channel hosts the page contacted (requests aborted, never sent)
    hotlinks: list[str] = field(default_factory=list)  # official brand domains the page loaded files from


@dataclass
class Brand:
    id: str
    name: str
    official_domains: list[str]
    keywords: list[str]
    exclude_tokens: list[str] = field(default_factory=list)
    search_queries: list[str] = field(default_factory=list)
    verified_by: str | None = None
    verified_at: str | None = None
    prior_points: dict[str, float] = field(default_factory=dict)  # short-keyword penalty measured per keyword


@dataclass
class SourceCfg:
    kind: Literal["enrich", "connector", "llm"]
    enabled: bool = True
    timeout_s: float = 8
    budget_per_hour: int | None = None
    budget_per_day: int | None = None
    data_mode: DataMode = "LIVE"
    key_env: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class Settings:  # config.load() -> Settings; read-only after start
    brands: list[Brand]
    sources: dict[str, SourceCfg]
    scoring: dict
    shared_infra: dict  # {asns: [int], ns_suffixes: [str], host_suffixes: [str], cidrs: [str]}
    data_dir: str
    port: int
    db_path: str
    evidence_dir: str
    secrets: dict[str, str]  # env values by NAME; never logged or rendered


class Budget(Protocol):  # backed by the `budgets` table; windows hour/day in UTC
    async def take(self, source: str, pool: Literal["manual", "auto"] = "auto") -> bool: ...

    async def remaining(self, source: str) -> dict: ...


@dataclass
class Ctx:  # passed to every enricher/connector
    settings: Settings
    http: httpx.AsyncClient
    resolver: dns.asyncresolver.Resolver
    budget: Budget
    pool: Literal["manual", "auto"]
    now: Callable[[], str]
