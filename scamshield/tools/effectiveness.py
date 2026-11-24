"""Effectiveness report for a live run (metrics M1..M11: M1 CT coverage, M2 uptime, M3 CT lag, M4 latency, M5 finds by source, M6 precision, M7 lead time vs phishing lists, M8 golden recall, M9 sieve noise, M10 cost, M11 integrity) from the run's SQLite file, written to docs/evidence/live-<run>.md.

    python -m scamshield.tools.effectiveness data/runs/<name> [more run dirs or .db files]

Read-only. A missing table or column gives "n/a", never a crash. Own finds (CT, search, pasted) and list echoes are always separate."""

from __future__ import annotations

import csv
import itertools
import math
import random
import sqlite3
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import yaml

from scamshield import config, live
from scamshield.enrich.lookalike import match

ROOT = Path(__file__).resolve().parents[2]
GST = timezone(timedelta(hours=4))
ECHO, SKIP = "feeds", ("baseline",)
CAVEATS = [
    "Cert logs: Let's Encrypt only (Willow, Sycamore).",
    'Lead time resolution is the list refresh interval; "before the lists we poll", not "before OpenPhish".',
    "Base rate of UAE fakes in the stream is unknown; zero finds is a fact, not a failure.",
    "Labellers are the builders; decoys are official domains, so they are easier to spot than real benign certs.",
]


def _open(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _has(conn, table: str, column: str | None = None) -> bool:
    cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
    return bool(cols) and (column is None or column in cols)


def _pct(values: list[float], q: float) -> float | None:
    values = sorted(values)
    return values[max(math.ceil(q * len(values)) - 1, 0)] if values else None


def _stats(values: list[float]) -> dict:
    return {"n": len(values), "p50": _pct(values, 0.5), "p95": _pct(values, 0.95), "max": max(values, default=None)}


def _wilson(tp: int, n: int) -> tuple[float, float] | None:
    if not n:
        return None
    z, p = 1.96, tp / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return round(centre - half, 3), round(centre + half, 3)


def _grade(value, limit, higher_better=True) -> str:
    if value is None:
        return "n/a"
    good = value >= limit if higher_better else value <= limit
    near = value >= limit * 0.9 if higher_better else value <= limit * 1.1
    return "GOOD" if good else "WARN" if near else "BAD"


def _gap_file(path: Path) -> list[tuple[datetime, datetime, str]]:
    out = []
    for line in path.read_text().splitlines() if path.exists() else []:
        parts = line.strip().split(",", 2)
        if len(parts) == 3 and (a := live.parse_ts(parts[0])) and (b := live.parse_ts(parts[1])):
            out.append((a, b, parts[2]))
    return out


def _overlap(a: datetime, b: datetime, spans: list[tuple[datetime, datetime]]) -> float:
    merged: list[list[datetime]] = []
    for s, e in sorted((max(s, a), min(e, b)) for s, e in spans if min(e, b) > max(s, a)):
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return sum((e - s).total_seconds() for s, e in merged)


def _loops(beats: list[dict], excused: list, restarts: list, gap_after: int) -> dict:
    result = {}
    for loop in sorted({b["loop"] for b in beats} - {"boot", "pause"}):
        ok = [b["at"] for b in beats if b["loop"] == loop and b["ok"]]
        gaps = []
        for a, b in itertools.pairwise(ok):
            if (b - a).total_seconds() > gap_after:
                excused_s = _overlap(a, b, [(s, e) for s, e, _ in excused])
                cause = next((r for s, e, r in excused if min(e, b) > max(s, a)), None) or (
                    "restart" if any(a <= t <= b for t, _ in restarts) else "unknown"
                )
                gaps.append(
                    {
                        "from": a,
                        "to": b,
                        "seconds": int((b - a).total_seconds()),
                        "excused_s": int(excused_s),
                        "unplanned_s": int((b - a).total_seconds() - excused_s),
                        "cause": cause,
                    }
                )
        window = (ok[-1] - ok[0]).total_seconds() if ok else 0
        down = sum(g["unplanned_s"] for g in gaps)
        denominator = max(window - sum(g["excused_s"] for g in gaps), 1)
        result[loop] = {
            "beats": len(ok),
            "gaps": gaps,
            "uptime_pct": round(100 - 100 * down / denominator, 2) if ok else None,
        }
    return result


def _golden_recall() -> dict:
    brands = config.load_brands(ROOT / "config" / "brands.yaml")
    golden = yaml.safe_load((ROOT / "tests" / "fixtures" / "lookalike_golden.yaml").read_text())["fake"]
    hit = sum(1 for g in golden if (m := match(g["fqdn"], brands)) and m["brand"] == g["brand"])
    return {"hit": hit, "total": len(golden)}


def _loose_misses(conn, conf) -> dict | None:
    if not _has(conn, "feed_index"):
        return None
    brands = config.load_brands(ROOT / "config" / "brands.yaml")
    keywords = {k for b in brands for k in b.keywords if len(k) >= 4}
    missed = [
        d
        for (d,) in conn.execute("SELECT domain FROM feed_index")
        if any(k in d for k in keywords) and not match(d, brands, mode="feed")
    ]
    sample = random.Random(conf["label"]["seed"]).sample(
        sorted(missed), min(len(missed), conf["label"]["sieve_sample"])
    )
    return {"missed": len(missed), "sample": sample}


def _finds(conn, echoes: bool) -> list[sqlite3.Row]:
    if not echoes and not _has(conn, "assessments"):
        return []  # no bands recorded: nothing qualifies as a find
    op = "=" if echoes else "NOT IN"
    return conn.execute(f"""SELECT d.id, d.fqdn, d.brand_id, d.found_by, d.first_seen_at FROM domains d WHERE d.data_mode = 'LIVE'
        {"" if echoes else "AND " + live.FIND_BANDS.format(alias="d")}
        AND d.found_by {op} {"'feeds'" if echoes else "('feeds', 'baseline')"} ORDER BY d.first_seen_at""").fetchall()


def compute(paths: list[str], run_dir: str | None = None) -> dict:
    conf = live.cfg()
    th = conf["thresholds"]
    conns = [_open(p) for p in paths]
    rd = Path(run_dir) if run_dir else None
    m: dict = {"paths": paths}
    beats = [
        {
            "at": live.parse_ts(r["at"]),
            **{k: r[k] for k in ("loop", "ok", "entries", "tree_size", "skipped", "candidates", "lag_s", "error")},
            "cursor": dict(r).get("cursor"),
        }  # old run DBs have no cursor column
        for c in conns
        if _has(c, "heartbeats")
        for r in c.execute("SELECT * FROM heartbeats ORDER BY at")
    ]
    has_beats = any(_has(c, "heartbeats") for c in conns)
    pauses = [(b["at"] - timedelta(seconds=b["lag_s"] or 0), b["at"], "pause") for b in beats if b["loop"] == "pause"]
    planned = _gap_file(rd / "planned_gaps") if rd else []
    restarts = []
    for line in (rd / "restarts.log").read_text().splitlines() if rd and (rd / "restarts.log").exists() else []:
        if t := live.parse_ts(line.split("\t")[0]):
            restarts.append((t, line.split("\t", 1)[-1]))
    m["pauses"], m["planned"], m["restarts"] = pauses, planned, restarts
    ct = sorted({b["loop"] for b in beats if b["loop"].startswith("ct:")})

    # M1 coverage, M2 uptime, M3 lag
    m["M1"] = m["M2"] = m["M3"] = None
    if has_beats:
        m["M1"] = {}
        for loop in ct:
            rows = [b for b in beats if b["loop"] == loop and b["ok"] and b["tree_size"]]
            read, skipped = sum(b["entries"] or 0 for b in rows), sum(b["skipped"] or 0 for b in rows)
            curs = [b for b in rows if b["cursor"] is not None]
            if (
                len(curs) > 1
            ):  # cursor is stored per cycle, so tiles of a killed cycle (no beat) still count; skips of the first beat precede its cursor
                read = max(curs[-1]["cursor"] - curs[0]["cursor"] - sum(b["skipped"] or 0 for b in curs[1:]), 0)
            growth = rows[-1]["tree_size"] - rows[0]["tree_size"] if rows else 0
            m["M1"][loop] = {
                "read": read,
                "skipped": skipped,
                "growth": growth,
                "coverage_pct": round(min(100 * read / growth, 100), 2) if growth > 0 else None,
            }
        m["M2"] = {"loops": _loops(beats, [*pauses, *planned], restarts, conf["gap_after_s"])}
        m["M3"] = {
            **_stats([b["lag_s"] for b in beats if b["loop"] in ct and b["ok"] and b["lag_s"] is not None]),
            "unit": "s",
        }
    m["feeds_refreshes"] = sum(
        1 for b in beats if b["loop"] == "feeds" and b["ok"] and not (b["error"] or "").startswith("skipped")
    )

    # M4 latency (needs jobs.created_at)
    m["M4"] = None
    if all(_has(c, "jobs", "created_at") for c in conns):
        ingest, queue, check, manual = [], [], [], []
        excused, excluded = [(s, e) for s, e, _ in [*pauses, *planned]], 0
        for c in conns:
            for r in c.execute("""SELECT d.found_by, d.first_seen_at, j.created_at, j.started_at, j.finished_at FROM domains d
                JOIN jobs j ON j.id = (SELECT min(id) FROM jobs WHERE target = d.fqdn AND kind = 'check_domain' AND created_at IS NOT NULL)
                WHERE d.data_mode = 'LIVE' AND d.found_by != 'baseline'"""):
                created, seen = live.parse_ts(r["created_at"]), live.parse_ts(r["first_seen_at"])
                started, finished = live.parse_ts(r["started_at"]), live.parse_ts(r["finished_at"])
                if r["found_by"] == "ct_tiled" and created and seen:
                    if _overlap(
                        seen, created, excused
                    ):  # waited across a machine pause or planned gap: not our latency
                        excluded += 1
                    else:
                        ingest.append((created - seen).total_seconds())
                if created and started:
                    queue.append((started - created).total_seconds())
                if started and finished:
                    check.append((finished - started).total_seconds())
                if r["found_by"] == "manual" and created and finished:
                    manual.append((finished - created).total_seconds())
        m["M4"] = {
            "ct_ingest": {**_stats(ingest), "excluded": excluded},
            "queue": _stats(queue),
            "check": _stats(check),
            "manual": {"n": len(manual), "within_60s": sum(x <= 60 for x in manual)},
        }

    # M5 finds per source and hour (GST), M6f echoes
    disc, echo, by_hour, per_day, finds = {}, {}, {}, {}, []
    for c in conns:
        for r in _finds(c, False):
            disc[r["found_by"]] = disc.get(r["found_by"], 0) + 1
            hour = live.parse_ts(r["first_seen_at"]).astimezone(GST).strftime("%m-%d %H:00")
            by_hour.setdefault(hour, {}).setdefault(r["found_by"], 0)
            by_hour[hour][r["found_by"]] += 1
            finds.append((c, r))
        for r in _finds(c, True):
            echo[ECHO] = echo.get(ECHO, 0) + 1
            day = live.parse_ts(r["first_seen_at"]).astimezone(GST).strftime("%Y-%m-%d")
            per_day[day] = per_day.get(day, 0) + 1
    m["M5"] = {"discovery": disc, "echoes": echo, "by_hour": by_hour}
    m["M6f"] = {"total": sum(echo.values()), "per_day": per_day, "refreshes": m["feeds_refreshes"]}

    # M6 precision over discovery finds only; M7 lead time
    tp = fp = unclear = auto = 0
    leads, within = [], 0
    for c, r in finds:
        verdict = None
        if _has(c, "feedback"):
            row = c.execute(
                "SELECT verdict FROM feedback WHERE domain_id = ? ORDER BY id DESC LIMIT 1", (r["id"],)
            ).fetchone()
            verdict = row["verdict"] if row else None
        listed = (
            c.execute("SELECT sources, first_listed_at FROM feed_index WHERE domain = ?", (r["fqdn"],)).fetchone()
            if _has(c, "feed_index")
            else None
        )
        if (
            verdict is None
            and listed
            and ("openphish" in listed["sources"].split(",") or len(listed["sources"].split(",")) >= 2)
        ):
            verdict, auto = "scam", auto + 1  # exact fqdn in OpenPhish or in two lists
        tp, fp, unclear = tp + (verdict == "scam"), fp + (verdict == "legit"), unclear + (verdict == "unclear")
        if listed and r["found_by"] in ("ct_tiled", "web search"):
            lead = (live.parse_ts(listed["first_listed_at"]) - live.parse_ts(r["first_seen_at"])).total_seconds()
            if lead > conf["refresh_interval_s"] + conf["lead_margin_s"]:
                leads.append(lead)
            else:
                within += 1
    labelled = tp + fp + unclear
    m["M6"] = {
        "tp": tp,
        "fp": fp,
        "unclear": unclear,
        "labelled": labelled,
        "total": len(finds),
        "auto_tp": auto,
        "wilson": _wilson(tp, tp + fp),
    }
    m["M7"] = {"claimed": len(leads), "median_s": _pct(leads, 0.5), "within_resolution": within}

    # M8 golden recall, M9 sieve noise, M10 cost
    m["M8"] = _golden_recall()
    certs = sum(b["entries"] or 0 for b in beats)
    hits = [r["fqdn"] for _, r in finds if r["found_by"] == "ct_tiled"]
    m["M9"] = {
        "certs": certs,
        "ct_hits": hits,
        "per_million": round(len(hits) * 1e6 / certs, 1) if certs else None,
        "loose": _loose_misses(conns[0], conf) if conns else None,
    }
    spend = [dict(r) for c in conns if _has(c, "llm_spend") for r in c.execute("SELECT day, est_usd FROM llm_spend")]
    tavily = [
        dict(r)
        for c in conns
        if _has(c, "budgets")
        for r in c.execute(
            "SELECT substr(window_start, 1, 10) AS day, sum(used) AS used FROM budgets WHERE source = 'tavily' GROUP BY day"
        )
    ]
    m["M10"] = {
        "llm_max_usd_day": max((s["est_usd"] for s in spend), default=0),
        "tavily_max_day": max((t["used"] for t in tavily), default=0),
        "bytes": "not measured",
    }

    # M11 integrity
    start = min((b["at"] for b in beats if b["loop"] == "boot"), default=None)
    syn = before = dup = baseline = 0
    for c in conns:
        syn += c.execute("SELECT count(*) FROM domains WHERE data_mode = 'SYNTHETIC'").fetchone()[0]
        syn += (
            c.execute("SELECT count(*) FROM facts WHERE data_mode = 'SYNTHETIC'").fetchone()[0]
            if _has(c, "facts")
            else 0
        )
        baseline += c.execute("SELECT count(*) FROM domains WHERE found_by = 'baseline'").fetchone()[0]
        if _has(c, "facts", "job_id"):
            dup += c.execute(
                "SELECT count(*) FROM (SELECT 1 FROM facts GROUP BY domain_id, type, source, job_id, value_json HAVING count(*) > 1)"
            ).fetchone()[0]
        if start and _has(c, "jobs", "created_at"):
            for r in c.execute("""SELECT j.created_at FROM domains d JOIN jobs j ON j.id = (SELECT min(id) FROM jobs WHERE target = d.fqdn AND created_at IS NOT NULL)
                                  WHERE d.data_mode = 'LIVE' AND d.found_by != 'baseline'"""):
                before += live.parse_ts(r["created_at"]) < start
    m["M11"] = {"synthetic": syn, "before_start": before, "duplicate_facts": dup, "baseline_rows_excluded": baseline}
    m["window"] = (min((b["at"] for b in beats), default=None), max((b["at"] for b in beats), default=None))

    window_s = (m["window"][1] - m["window"][0]).total_seconds() if m["window"][0] else 0
    ups = {
        loop: v["uptime_pct"] for loop, v in (m["M2"] or {"loops": {}})["loops"].items() if v["uptime_pct"] is not None
    }
    m4 = m["M4"] or {}
    graded = (
        [
            _grade(m["M4"]["ct_ingest"]["p95"], th["m4_ct_ingest_p95_s"], False)
            if m["M4"] and m["M4"]["ct_ingest"]["n"]
            else "n/a",
            _grade(m["M4"]["check"]["p95"], th["m4_check_p95_s"], False)
            if m["M4"] and m["M4"]["check"]["n"]
            else "n/a",
        ]
        if m4
        else ["n/a"]
    )
    order = ["n/a", "GOOD", "WARN", "BAD"]
    worst = lambda grades: max((g for g in grades if g != "n/a"), key=order.index, default="n/a")
    covs = [v["coverage_pct"] for v in (m["M1"] or {}).values() if v["coverage_pct"] is not None]
    m["verdicts"] = {
        "M1": worst([_grade(min(covs), th["m1_coverage_pct"])])
        if covs and window_s >= conf["min_window_s"]
        else "n/a",  # the unread tail of a short window is not a loss
        "M2": worst(
            [
                _grade(v, th["m2_worker_uptime_pct"] if k == "worker" else th["m2_ct_uptime_pct"])
                for k, v in ups.items()
                if k == "worker" or k.startswith("ct:")
            ]
        ),
        "M3": _grade(m["M3"]["p95"], th["m3_lag_p95_s"], False) if m["M3"] and m["M3"]["n"] else "n/a",
        "M4": worst(graded),
        "M10": worst(
            [
                _grade(m["M10"]["llm_max_usd_day"], th["m10_llm_usd_day"], False),
                _grade(m["M10"]["tavily_max_day"], th["m10_tavily_day"], False),
            ]
        ),
        "M11": "BAD" if syn or before or dup else "GOOD",
    }
    return m


def _t(moment: datetime | None) -> str:
    return moment.astimezone(GST).strftime("%m-%d %H:%M") if moment else "-"


def _dur(seconds) -> str:
    return (
        "-"
        if seconds is None
        else f"{int(seconds // 3600)}h{int(seconds % 3600 // 60):02d}m"
        if seconds >= 3600
        else f"{int(seconds)} s"
    )


def render(m: dict, name: str) -> str:
    na = "n/a (run predates heartbeats)"
    v, M4, M6 = m["verdicts"], m["M4"], m["M6"]
    start, end = m["window"]
    hours = round((end - start).total_seconds() / 3600, 1) if start and end else 0
    certs = m["M9"]["certs"]
    out = [
        f"# Live run {name}: effectiveness report",
        f"Window (GST): {_t(start)} to {_t(end)} ({hours} h). Generated {_t(datetime.now(UTC))}. Times are GST.",
        "",
        "Verdict: " + " · ".join(f"{k} {g}" for k, g in v.items()),
        "Gate: M1, M2, M3, M4, M11 must be GOOD. BAD on any of them = not reliable, fix before relying on the run. Zero real CT finds is not BAD.",
        "",
        "## Summary",
        f"1. Ran {hours} h; read {certs:,} certificates (Let's Encrypt); machine pauses: {len(m['pauses'])}, watchdog restarts: {len(m['restarts'])}.",
        f"2. Our own finds (certificates, search, pasted links): {sum(m['M5']['discovery'].values())}; confirmed as fakes by a person: {M6['tp'] - M6['auto_tp']}.",
        f"3. Echoes of other phishing lists: {m['M6f']['total']} - a pipeline check, not our own detection; not counted in precision.",
        f"4. Integrity (M11): {v['M11']}; false SYNTHETIC labels: {m['M11']['synthetic']}.",
        f"5. Confirmed fakes so far: {M6['tp']}; the interval below shows how little that proves.",
        "",
        "## Metrics",
        "| # | Metric | Value | Verdict |",
        "|---|---|---|---|",
    ]
    if m["M1"] is None:
        out += [f"| M1 | CT coverage | {na} | n/a |", f"| M2 | Uptime | {na} | n/a |", f"| M3 | CT lag | {na} | n/a |"]
    else:
        out += [
            "| M1 | CT coverage (read / tree growth; skipped listed) | "
            + "; ".join(
                f"{k} {x['coverage_pct']}% (read {x['read']}, skipped {x['skipped']})" for k, x in m["M1"].items()
            )
            + f" | {v['M1']} |",
            "| M2 | Uptime (unplanned gaps only) | "
            + "; ".join(f"{k} {x['uptime_pct']}%" for k, x in m["M2"]["loops"].items())
            + f" | {v['M2']} |",
            f"| M3 | CT lag p50/p95/max | {_dur(m['M3']['p50'])} / {_dur(m['M3']['p95'])} / {_dur(m['M3']['max'])} (n={m['M3']['n']}) | {v['M3']} |",
        ]
    if M4 is None:
        out.append("| M4 | Latency | n/a (run predates jobs.created_at) | n/a |")
    else:
        ci_note = f" (excluded {M4['ct_ingest']['excluded']} (machine pause))" if M4["ct_ingest"]["excluded"] else ""
        s = lambda d: f"p50 {_dur(d['p50'])} p95 {_dur(d['p95'])} (n={d['n']})"
        out.append(
            f"| M4 | Latency | CT ingest {s(M4['ct_ingest'])}{ci_note}; queue {s(M4['queue'])}; check {s(M4['check'])}; pasted ≤60 s: {M4['manual']['within_60s']}/{M4['manual']['n']} | {v['M4']} |"
        )
    w = M6["wilson"]
    m7, m9, m10, m11 = m["M7"], m["M9"], m["M10"], m["M11"]
    out += [
        f"| M6 | Precision, discovery only | TP {M6['tp']} · FP {M6['fp']} · unclear {M6['unclear']} · {M6['labelled']} of {M6['total']} labelled (auto TP {M6['auto_tp']}) · Wilson 95% {w if w else 'n/a'} | info |",
        f"| M6f | List echoes | {m['M6f']['total']} over {m['M6f']['refreshes']} refreshes; not detection | info |",
        f"| M7 | Lead time vs lists we poll | claimed {m7['claimed']}, median {_dur(m7['median_s'])}; within polling resolution {m7['within_resolution']} | info |",
        f"| M8 | Golden recall | {m['M8']['hit']}/{m['M8']['total']} | {'GOOD' if m['M8']['hit'] == m['M8']['total'] else 'BAD'} |",
        f"| M9 | Sieve noise | {len(m9['ct_hits'])} CT hits in {certs:,} certificates ({m9['per_million']} per million) | info |".replace(
            ",", " "
        ),
        f"| M10 | Cost | LLM max ${m10['llm_max_usd_day']}/day · Tavily max {m10['tavily_max_day']}/day · bytes {m10['bytes']} | {v['M10']} |",
        f"| M11 | Integrity | SYNTHETIC {m11['synthetic']} · finds before run start {m11['before_start']} · duplicate facts {m11['duplicate_facts']} · baseline rows excluded {m11['baseline_rows_excluded']} | {v['M11']} |",
        "",
        "## Our finds (discovery)",
        "| Hour (GST) | " + " | ".join(sorted(m["M5"]["discovery"])) + " |",
        "|---|" + "---|" * len(m["M5"]["discovery"]),
    ]
    out += [
        f"| {h} | " + " | ".join(str(c.get(s, 0)) for s in sorted(m["M5"]["discovery"])) + " |"
        for h, c in sorted(m["M5"]["by_hour"].items())
    ]
    if not m["M5"]["discovery"]:
        out.append("No finds of our own in this window.")
    out += ["", "## List echoes (not our detections)", "| Day (GST) | New brand domains in lists |", "|---|---|"]
    out += [f"| {d} | {n} |" for d, n in sorted(m["M6f"]["per_day"].items())]
    out += ["", "## CT hits (every one needs a label)"] + [f"- {h}" for h in m9["ct_hits"]]
    if m9["loose"]:
        out += [
            "",
            f"## M9a loose selector: {m9['loose']['missed']} listed names carry a brand keyword but strict match misses them (sample)",
        ] + [f"- {d}" for d in m9["loose"]["sample"]]
    out += ["", "## Gaps, pauses, restarts"]
    gaps = [(loop, g) for loop, x in (m["M2"] or {"loops": {}})["loops"].items() for g in x["gaps"]]
    out += [
        f"- {loop}: {_t(g['from'])} to {_t(g['to'])}, {_dur(g['seconds'])}, excused {_dur(g['excused_s'])}, unplanned {_dur(g['unplanned_s'])}, cause: {g['cause']}"
        for loop, g in gaps
    ] or ["- no gaps"]
    out += [f"- PAUSE (machine asleep or frozen) {_t(s)} to {_t(e)}" for s, e, _ in m["pauses"]]
    out += [f"- planned {_t(s)} to {_t(e)}: {why}" for s, e, why in m["planned"]]
    out += [f"- restart {_t(t)}: {why}" for t, why in m["restarts"]]
    out += ["", "## Caveats", *[f"- {c}" for c in CAVEATS]]
    return "\n".join(out) + "\n"


def export_labels(paths: list[str], out: str) -> None:
    """Blind CSV (fqdn, brand, source only), shuffled, with decoys mixed in; the key to the decoys goes to a separate file."""
    conf = live.cfg()["label"]
    rows = [(r["fqdn"], r["brand_id"] or "", r["found_by"]) for p in paths for r in _finds(_open(p), False)]
    brands = config.load_brands(ROOT / "config" / "brands.yaml")
    rng = random.Random(conf["seed"])
    pool = [(d, b.id) for b in brands for d in b.official_domains]
    decoys = rng.sample(pool, min(len(pool), max(1, round(len(rows) * conf["decoy_share"])) if rows else 0))
    rows += [(d, brand, "ct_tiled") for d, brand in decoys]
    rng.shuffle(rows)
    key = {d for d, _ in decoys}
    with open(out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["fqdn", "brand", "source"])
        writer.writerows(rows)
    with open(Path(out).with_name(Path(out).stem + "_key.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["fqdn", "decoy"])
        writer.writerows((fqdn, int(fqdn in key)) for fqdn, _, _ in rows)


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    run_dir = next((Path(a) for a in argv if Path(a).is_dir()), None)
    dbs = [str(Path(a) / "scamshield.db") if Path(a).is_dir() else a for a in argv]
    name = run_dir.name if run_dir else Path(dbs[0]).stem
    m = compute(dbs, str(run_dir) if run_dir else None)
    out = ROOT / "docs" / "evidence" / f"live-{name}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(m, name), encoding="utf-8")
    export_labels(dbs, str(run_dir / "to_label.csv" if run_dir else out.with_suffix(".csv")))
    print(f"{out}\nVerdict: " + " · ".join(f"{k} {g}" for k, g in m["verdicts"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
