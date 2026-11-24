"""Load config/*.yaml and env into Settings. Every number and threshold lives in the yaml files."""

from __future__ import annotations

import copy
import os
from pathlib import Path

import yaml

from scamshield.contracts import Brand, Settings, SourceCfg

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
SECRET_NAMES = (
    "ANTHROPIC_API_KEY",
    "TAVILY_API_KEY",
    "CERTSPOTTER_API_KEY",
    "ABUSECH_AUTH_KEY",
    "URLSCAN_API_KEY",
    "CT_CONTACT_EMAIL",
)
SOURCE_KEYS = {"kind", "enabled", "timeout_s", "budget_per_hour", "budget_per_day", "data_mode", "key_env"}


_YAML_CACHE: dict[str, tuple[int, object]] = {}


def _yaml(path: Path):
    """Parsed YAML, re-read only when the file changes (the queue read ui.yaml twice per row: 2186 parses, ~4 s per page).
    A deep copy is returned: callers (and tests) may change their settings without touching the cache."""
    mtime = os.stat(path).st_mtime_ns
    cached = _YAML_CACHE.get(str(path))
    if cached is None or cached[0] != mtime:
        with open(path, encoding="utf-8") as f:
            cached = _YAML_CACHE[str(path)] = (mtime, yaml.safe_load(f))
    return copy.deepcopy(cached[1])


def load_brands(path: Path) -> list[Brand]:
    raw = _yaml(path)
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{path}: expected a non-empty list of brands")
    brands, seen = [], set()
    for item in raw:
        for key in ("id", "name", "official_domains", "keywords"):
            if not item.get(key):
                raise ValueError(f"{path}: brand {item.get('id')!r} missing {key}")
        if item["id"] in seen:
            raise ValueError(f"{path}: duplicate brand id {item['id']}")
        seen.add(item["id"])
        brands.append(
            Brand(
                id=item["id"],
                name=item["name"],
                official_domains=[d.lower() for d in item["official_domains"]],
                keywords=[k.lower() for k in item["keywords"]],
                exclude_tokens=item.get("exclude_tokens") or [],
                search_queries=item.get("search_queries") or [],
                verified_by=item.get("verified_by"),
                verified_at=item.get("verified_at"),
                prior_points=item.get("prior_points") or {},
            )
        )
    return brands


def load_sources(path: Path) -> dict[str, SourceCfg]:
    raw = _yaml(path)
    sources = {}
    for name, item in raw.items():
        if item.get("kind") not in ("enrich", "connector", "llm"):
            raise ValueError(f"{path}: source {name} has invalid kind {item.get('kind')!r}")
        sources[name] = SourceCfg(
            **{k: v for k, v in item.items() if k in SOURCE_KEYS},
            extra={k: v for k, v in item.items() if k not in SOURCE_KEYS},
        )
    return sources


def load() -> Settings:
    scoring = _yaml(CONFIG_DIR / "scoring.yaml")
    for key in (
        "rule_version",
        "points",
        "bands",
        "beta",
        "thresholds",
        "edge",
        "guards",
        "lookalike",
        "smishing",
        "snapshot",
    ):
        if key not in scoring:
            raise ValueError(f"scoring.yaml: missing {key}")
    shared = _yaml(CONFIG_DIR / "shared_infra.yaml")
    for key in ("asns", "ns_suffixes", "host_suffixes", "cidrs"):
        shared.setdefault(key, [])
    data_dir = os.environ.get("SCAMSHIELD_DATA_DIR") or "data"
    return Settings(
        brands=load_brands(CONFIG_DIR / "brands.yaml"),
        sources=load_sources(CONFIG_DIR / "sources.yaml"),
        scoring=scoring,
        shared_infra=shared,
        data_dir=data_dir,
        port=int(os.environ.get("PORT") or 8000),
        db_path=str(Path(data_dir) / "scamshield.db"),
        evidence_dir=str(Path(data_dir) / "evidence"),
        secrets={n: os.environ[n] for n in SECRET_NAMES if os.environ.get(n)},
    )
