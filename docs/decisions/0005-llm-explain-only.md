# ADR 0005: Anthropic Claude for explanations only; deterministic scoring
Date: 2026-11-19 · Status: accepted

## Decision
- Risk, coverage, state and graph edges are computed by deterministic code (`scoring.py`, `graph.py`). The LLM
  never writes to them.
- `explain.py` calls the Anthropic Messages API (official `anthropic` SDK), model from env `ANTHROPIC_MODEL`,
  default `claude-sonnet-5-5` (maintainer's choice; verify the exact ID against Anthropic docs when implementing).
  No tools, `max_tokens` 1200, timeout 30 s, 1 retry.
- Output: strict JSON (summary, supporting/counter claims each with evidence_ids, uncertainties, cannot_determine).
  Validator rejects unknown evidence IDs → "AI explanation unavailable".
- Site content is untrusted: truncated to 4 KB, wrapped in `<untrusted_page_text>`, system prompt says it is data,
  never instructions. Analyst notes are never sent.
- When: automatically once for manual checks; automatically for at most 20 discovered domains per day (highest risk
  in REVIEW_HIGH, not IN_FEED-only); otherwise on click. ~1,100 feed candidates never trigger calls in bulk.
- Cached by assessment ID; tokens per call in `explanations`; daily counter `llm_spend` with prices from `.env`;
  hard cap `LLM_DAILY_CAP_USD=15` (maintainer decision).

## Why
The maintainer has an Anthropic balance; explanation quality matters to reviewers, but trust requires that numbers come from
rules with evidence. Prompt injection cannot change scores because the model has no write path.

## Consequences
LLM outage only hides the explanation. Switching provider = rewrite `explain.py` only.
