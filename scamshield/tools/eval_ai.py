"""Evaluation of the AI judge before it may sort the queue.

    python -m scamshield.tools.eval_ai --labels <reviewed-labels.md> --db <run>/scamshield.db [...]
    python -m scamshield.tools.eval_ai --live [--max-usd 0.25]     # the only mode that calls the paid API

Without --live nothing is sent anywhere: it prints which labelled rows are gray in the run database, the expected cost,
and the formula-only ranking. With --live it asks the judge once per gray labelled row (UNSURE rows are skipped), writes
the answers to fixtures/labelled/ai_runs/<date>.jsonl and the report to <out>/ai-eval-<date>.md (--out, default docs/evidence).
The run database is opened read-only; the judge's answers are never written into it.

Labels: the reviewed markdown table, column 4 = final mark: F -> UAE_FAKE (OTHER_PHISH when the comment says
"not a UAE brand"), NF -> NOT_FAKE, U -> UNSURE (excluded, counted)."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from scamshield import config, db, explain, triage_ai

ROOT = Path(__file__).resolve().parents[2]
_MARK = {"F": "UAE_FAKE", "NF": "NOT_FAKE", "U": "UNSURE"}
BARS = {"accuracy": 0.85, "unclear": 0.30, "ranking": 0.40, "valid": 0.98, "usd": 0.001, "p90_s": 5.0}


def load_labels(path: Path) -> dict[str, str]:
    """fqdn -> label from the reviewed markdown table."""
    labels = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 7 or not cells[0].isdigit():
            continue
        fqdn, mark, comment = cells[1].strip("`"), cells[3].strip("*"), cells[6]
        label = _MARK.get(mark.upper())
        if label == "UAE_FAKE" and re.search(r"not a UAE brand", comment, re.IGNORECASE):
            label = "OTHER_PHISH"
        if label:
            labels[fqdn.lower()] = label
    return labels


def _open(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def gray_rows(conns: list, labels: dict[str, str], cfg: dict) -> tuple[list[dict], dict]:
    """Labelled rows whose newest assessment is gray, with the judge's input; plus counts of the rest. Per domain the
    first database that has an assessment for it is used (the labels came from several runs)."""
    rows, counts = [], {"labelled": len(labels), "not_in_db": 0, "not_gray": 0, "unsure": 0}
    sql = """SELECT d.id, a.risk_score, a.flags_json FROM domains d JOIN assessments a ON a.id = (SELECT max(id) FROM assessments WHERE domain_id = d.id)
             WHERE d.fqdn = ?"""
    for fqdn, label in sorted(labels.items()):
        conn, found = next(((c, hit) for c in conns if (hit := c.execute(sql, (fqdn,)).fetchone())), (None, None))
        if found is None:
            counts["not_in_db"] += 1
            continue
        flags = json.loads(found["flags_json"])
        if not set(cfg["bands"]) & set(flags):
            counts["not_gray"] += 1
            continue
        if label == "UNSURE":
            counts["unsure"] += 1
            continue
        message, known = triage_ai.build_input(conn, found["id"], cfg)
        brand = triage_ai.brand_name(triage_ai._brand(conn, found["id"]))
        rows.append(
            {
                "fqdn": fqdn,
                "label": label,
                "risk": found["risk_score"] or 0,
                "flags": flags,
                "message": message,
                "known": known,
                "brand": brand,
            }
        )
    return rows, counts


def expected_cost(rows: list[dict], cfg: dict) -> tuple[float, float]:
    """(typical, worst case) dollars: typical = 4 chars per token and 300 output tokens; worst = every retry, full output."""
    price, system = cfg["price_per_mtok"], len(triage_ai.SYSTEM)
    typical = sum((system + len(r["message"])) / 4 * price["input"] + 300 * price["output"] for r in rows) / 1e6
    worst = (
        sum(
            (1 + cfg["output_retries"])
            * ((system + len(r["message"])) / 3 * price["input"] + cfg["max_tokens"] * price["output"])
            for r in rows
        )
        / 1e6
    )
    return typical, worst


def ranking_share(rows: list[dict], demote: dict[str, bool]) -> float | None:
    """Share of non-UAE gray rows ranked below every UAE_FAKE gray row (GRAY before GRAY_LOW, then risk; demoted rows last in their tier)."""
    order = sorted(rows, key=lambda r: ("GRAY_LOW" in r["flags"], demote.get(r["fqdn"], False), -r["risk"]))
    fakes = [i for i, r in enumerate(order) if r["label"] == "UAE_FAKE"]
    others = [i for i, r in enumerate(order) if r["label"] != "UAE_FAKE"]
    if not fakes or not others:
        return None
    return sum(i > max(fakes) for i in others) / len(others)


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def report(
    rows: list[dict], results: list[dict], counts: dict, ranked_formula: float | None, cfg: dict
) -> tuple[str, bool]:
    answered = [r for r in results if r["valid"]]
    decided = [r for r in answered if r["answer"]["brand_meant"] in ("yes", "no")]
    correct = [r for r in decided if (r["answer"]["brand_meant"] == "yes") == (r["label"] == "UAE_FAKE")]
    fakes_no = [
        r["fqdn"]
        for r in answered
        if r["label"] == "UAE_FAKE" and r["answer"]["brand_meant"] == "no" and r["answer"]["confidence"] == "high"
    ]
    unclear = sum(r["answer"]["brand_meant"] == "unclear" for r in answered) / len(answered) if answered else None
    accuracy = len(correct) / len(decided) if decided else None
    demote = {
        r["fqdn"]: triage_ai.effect(r["answer"] if r["valid"] else None, r["flags"], r["brand"])["demote"]
        for r in results
    }
    ranked_ai = ranking_share(rows, demote)
    valid = len(answered) / len(results) if results else None
    usd = sum(r["usd"] for r in results) / len(results) if results else None
    latencies = sorted(r["seconds"] for r in results)
    p90 = latencies[min(len(latencies) - 1, int(0.9 * len(latencies)))] if latencies else None
    checks = {
        "UAE_FAKE judged no (high) = 0": not fakes_no,
        f"accuracy on decided >= {BARS['accuracy']:.0%}": accuracy is not None and accuracy >= BARS["accuracy"],
        f"unclear <= {BARS['unclear']:.0%}": unclear is not None and unclear <= BARS["unclear"],
        f"ranking >= {BARS['ranking']:.0%} and above formula alone": ranked_ai is not None
        and ranked_ai >= BARS["ranking"]
        and (ranked_formula is None or ranked_ai > ranked_formula),
        f"schema-valid >= {BARS['valid']:.0%}": valid is not None and valid >= BARS["valid"],
        f"cost <= ${BARS['usd']} per domain": usd is not None and usd <= BARS["usd"],
        f"latency p90 <= {BARS['p90_s']:g} s": p90 is not None and p90 <= BARS["p90_s"],
    }
    passed = all(checks.values())
    lines = [
        f"# AI judge evaluation {datetime.now(UTC).date()} — {'PASSED' if passed else 'NOT PASSED'} ({cfg['model']}, {cfg['prompt_version']})",
        "",
        f"Labelled rows: {counts['labelled']}; not in the run DB: {counts['not_in_db']}; not gray: {counts['not_gray']}; gray but UNSURE (skipped): {counts['unsure']}; judged: {len(results)}.",
        "Labels: two AI reviewers, not the maintainer or police (see the labels file). Train/holdout split: not available in this label set, one group.",
        "",
        "| Metric | Value | Bar | OK |",
        "|---|---|---|---|",
        f"| UAE_FAKE judged no (high) | {len(fakes_no)} {', '.join(fakes_no)} | 0 | {'yes' if not fakes_no else 'NO'} |",
        f"| Accuracy on decided (yes/no vs label) | {_pct(accuracy)} of {len(decided)} | ≥ 85 % | {'yes' if checks[list(checks)[1]] else 'NO'} |",
        f"| Unclear share | {_pct(unclear)} | ≤ 30 % | {'yes' if checks[list(checks)[2]] else 'NO'} |",
        f"| Ranking: non-UAE gray rows below every UAE_FAKE | formula {_pct(ranked_formula)} → with judge {_pct(ranked_ai)} | ≥ 40 % and higher | {'yes' if checks[list(checks)[3]] else 'NO'} |",
        f"| Schema-valid outputs | {_pct(valid)} | ≥ 98 % | {'yes' if checks[list(checks)[4]] else 'NO'} |",
        f"| Cost per domain | ${usd:.5f} | ≤ $0.001 | {'yes' if checks[list(checks)[5]] else 'NO'} |"
        if usd is not None
        else "| Cost per domain | n/a | ≤ $0.001 | NO |",
        f"| Latency p90 | {p90:.1f} s | ≤ 5 s | {'yes' if checks[list(checks)[6]] else 'NO'} |"
        if p90 is not None
        else "| Latency p90 | n/a | ≤ 5 s | NO |",
        "",
        "Injection cases: covered by recorded-response tests (tests/test_triage_ai.py), not by this live run.",
        "",
        "| Domain | Label | Judge | Confidence | Error |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| `{r['fqdn']}` | {r['label']} | {r['answer']['brand_meant'] if r['valid'] else '—'} | {r['answer']['confidence'] if r['valid'] else '—'} | {r['error'] or ''} |"
        for r in results
    ]
    if ranked_ai is not None and ranked_formula is not None and ranked_ai <= ranked_formula:
        lines += [
            "",
            "AI adds cost without benefit on this set: sorting stays off (llm.yaml judge.sort_enabled: false).",
        ]
    return "\n".join(lines) + "\n", passed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m scamshield.tools.eval_ai", description=__doc__.splitlines()[0])
    parser.add_argument(
        "--labels", type=Path, required=True, help="reviewed labels markdown table (see the module docstring)"
    )
    parser.add_argument(
        "--db",
        type=Path,
        nargs="+",
        required=True,
        help="databases where the labelled finds were stored (not the live run); opened read-only, first hit wins",
    )
    parser.add_argument("--live", action="store_true", help="call the paid API (otherwise a dry run: nothing is sent)")
    parser.add_argument(
        "--max-usd", type=float, default=0.25, help="refuse a live run whose worst-case cost is above this"
    )
    parser.add_argument("--out", type=Path, default=ROOT / "docs/evidence")
    parser.add_argument("--runs", type=Path, default=ROOT / "fixtures/labelled/ai_runs")
    parser.add_argument(
        "--spend-db",
        type=Path,
        default=None,
        help="app database whose llm_spend holds the shared daily AI cap (default: the app's, SCAMSHIELD_DATA_DIR)",
    )
    args = parser.parse_args(argv)
    missing = [str(p) for p in args.db if not p.exists()]
    if missing:
        print(f"run database not found: {', '.join(missing)} (check the --db paths)")
        return 2
    cfg = triage_ai._cfg()
    labels = load_labels(args.labels)
    conns = [_open(p) for p in args.db]
    try:
        rows, counts = gray_rows(conns, labels, cfg)
    finally:
        for conn in conns:
            conn.close()
    typical, worst = expected_cost(rows, cfg)
    ranked_formula = ranking_share(rows, {})
    print(
        f"labels: {counts['labelled']} rows from {args.labels.name}; not in DB {counts['not_in_db']}, not gray {counts['not_gray']}, gray UNSURE skipped {counts['unsure']}"
    )
    print(
        f"gray labelled rows to judge: {len(rows)} ({sum(r['label'] == 'UAE_FAKE' for r in rows)} UAE_FAKE) with {cfg['model']}"
    )
    print(f"expected cost: about ${typical:.4f}, at most ${worst:.4f}")
    print(f"formula-only ranking (non-UAE gray rows below every UAE_FAKE): {_pct(ranked_formula)}")
    if not args.live:
        print("dry run: no API call made. Add --live to run the judge (paid).")
        return 0
    if worst > args.max_usd:
        print(f"refused: worst case ${worst:.4f} is above --max-usd {args.max_usd}")
        return 2
    client = triage_ai._client()
    if client is None:
        print("no API key (ANTHROPIC_API_KEY): nothing was sent")
        return 2
    spend_db = Path(args.spend_db or config.load().db_path)
    if not spend_db.exists():  # never create an empty app DB: its llm_spend would know nothing of today's spend
        print(f"app database not found: {spend_db} (pass --spend-db or set SCAMSHIELD_DATA_DIR); nothing was sent")
        return 2
    db.init(str(spend_db))  # the eval's spend counts against the same $/day cap as the app
    refusal, spend_day = asyncio.run(db.run(explain.reserve, worst))
    if refusal:
        print(f"refused: {refusal}; nothing was sent")
        return 2
    results, answered, unanswered = [], [], 0
    for row in rows:
        started = time.monotonic()
        result, usages = triage_ai.ask(client, cfg, row["message"], row["known"])
        paid = triage_ai.SimpleUsage.total(usages)
        answered += usages
        unanswered += isinstance(result, triage_ai.JudgeError) and result.reason in ("timeout", "api_error")
        valid = not isinstance(result, triage_ai.JudgeError)
        results.append(
            {
                "fqdn": row["fqdn"],
                "label": row["label"],
                "flags": row["flags"],
                "brand": row["brand"],
                "valid": valid,
                "answer": result if valid else None,
                "error": None if valid else f"{result.reason}: {result.detail}",
                "seconds": time.monotonic() - started,
                "usd": explain.cost_usd(paid, cfg["price_per_mtok"]) if paid else 0.0,
                "input_tokens": paid.input_tokens if paid else None,
                "output_tokens": paid.output_tokens if paid else None,
            }
        )
    total = triage_ai.SimpleUsage.total(answered)

    def settle(
        conn,
    ):  # real cost when every ask was answered; else the whole reservation stays (a lost answer may be billed)
        explain.settle_in(
            conn,
            None if unanswered else total,
            cfg["price_per_mtok"],
            worst,
            calls=max(len(answered), 1),
            day=spend_day,
        )
        conn.commit()

    asyncio.run(db.run(settle))
    day = datetime.now(UTC).date().isoformat()
    args.runs.mkdir(parents=True, exist_ok=True)
    (args.runs / f"{day}.jsonl").write_text(
        "".join(
            json.dumps({**r, "model": cfg["model"], "prompt_version": cfg["prompt_version"]}, ensure_ascii=False) + "\n"
            for r in results
        ),
        encoding="utf-8",
    )
    text, passed = report(rows, results, counts, ranked_formula, cfg)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / f"ai-eval-{day}.md").write_text(text, encoding="utf-8")
    print(text)
    print(f"spent about ${sum(r['usd'] for r in results):.4f}; report: {args.out / f'ai-eval-{day}.md'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
