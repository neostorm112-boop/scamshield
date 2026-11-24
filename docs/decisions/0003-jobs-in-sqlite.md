# ADR 0003: Durable job queue in a SQLite table + in-process asyncio worker (no Redis, no Celery)
Date: 2026-11-19 · Status: accepted

## Decision
`jobs` table (status, priority, attempts, run_after, idem_key UNIQUE). The worker is an asyncio loop started in the
FastAPI lifespan: polls every 2 s, claims a job atomically with `UPDATE jobs SET status='running' WHERE id=(SELECT id … LIMIT 1)
RETURNING *`, runs
≤ 3 light jobs + 1 browser job at a time, exponential backoff with jitter, `partial` when some sources failed.
Schedules (feeds 6 h, search 6 h, re-checks) are rows with `run_after`, created by the worker itself.
On startup, rows in `running` are reset to `queued` (restart survival). Browser work runs in a subprocess.

## Why
One user and tens of jobs per minute; Redis/Celery would add a service and a second process to start and debug.
Idempotency key prevents duplicate work after crashes.

## Consequences / reversal cost
Low: job functions are plain async functions; swapping the loop for a real queue later touches `worker.py` only.
