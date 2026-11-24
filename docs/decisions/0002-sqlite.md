# ADR 0002: SQLite (WAL) as the only database, not PostgreSQL
Date: 2026-11-19 · Status: accepted

## Context
The original plan suggested PostgreSQL + pgvector, allowing SQLite as a light profile. The v1 scope removed RAG/vector
search. One analyst, one machine, data volume: ~500 k feed rows, thousands of domains, tens of thousands of facts.

## Decision
SQLite file `data/scamshield.db`, WAL mode, `busy_timeout=5000`, stdlib `sqlite3`, plain SQL in `schema.sql`
(`CREATE TABLE IF NOT EXISTS`), no ORM. One connection per thread; all calls go through
`await db.run(fn)` (asyncio.to_thread) so the event loop never blocks. Requires SQLite ≥ 3.35 (RETURNING), checked
at startup. Graph math in NetworkX loaded from the `edges` table on read.

## Why
- Zero install, zero server, survives restart, backup = copy one file. Postgres needs a service (brew/Docker) on
  every teammate's laptop — a real risk in a 20 h rebuild.
- Volume and concurrency (1 user, 1 writer process) are far below SQLite limits.
- pgvector not needed: "similar to confirmed case" uses graph edges, not embeddings.

## Consequences / reversal cost
- Moving to Postgres later: SQL is mostly portable (avoid SQLite-only tricks; timestamps stored as ISO-8601 UTC
  text; JSON as TEXT). Medium cost, mostly mechanical.
- Multi-user / server deployment would require Postgres — out of scope for v1.
