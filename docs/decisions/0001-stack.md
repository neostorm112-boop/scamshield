# ADR 0001: One Python process — FastAPI + server-rendered HTML (Jinja2 + htmx), no Docker
Date: 2026-11-19 · Status: accepted

## Context
Must run on one laptop (worst case 8 GB MacBook), start with one command, survive restart, and be rebuilt from
scratch by 3–5 people with AI assistants in ~20 h. Scraping, DNS, Playwright, NetworkX and the Anthropic SDK are
all first-class in Python.

## Decision
- Backend: Python 3.12 + FastAPI + uvicorn, single process; background worker runs as an asyncio task in the app
  lifespan (see ADR 0003).
- UI: Jinja2 server-rendered pages + htmx (live polling/partial updates) + cytoscape.js (graph). Vendored static
  files, no npm, no build step.
- Start: `./run.sh` (venv + pip + `playwright install chromium` on first run + schema apply + uvicorn on 127.0.0.1).
- No Docker requirement.

## Why
- One language, one process → every teammate can run and debug everything; AI assistants generate this stack reliably.
- Server-rendered pages need no separate JSON API, state store or bundler — roughly halves UI work vs an SPA.
- Docker Desktop on an 8 GB Mac costs ~2 GB RAM and adds a failure mode at the demo; nothing here needs it.

## Consequences / reversal cost
- UI is less "app-like"; acceptable for analyst screens. Moving to an SPA later = add JSON routes; templates are thin.
- If the demo machine is not a Mac, `run.sh` must work on Linux too (same commands). Windows: not supported in v1.
- Venue Wi-Fi risk: wheels pre-downloaded into `wheelhouse/` and Chromium installed before the event; `run.sh`
  prefers the local wheelhouse.
