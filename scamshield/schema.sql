-- Meaning of every table: docs/specs/scamshield/DATA.md. Idempotent: safe to run on every start.
CREATE TABLE IF NOT EXISTS sources (
  name TEXT PRIMARY KEY, kind TEXT NOT NULL, data_mode TEXT NOT NULL DEFAULT 'LIVE',
  enabled INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'ok',
  last_success_at TEXT, last_error TEXT, last_error_at TEXT, calls_today INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT, fqdn TEXT NOT NULL UNIQUE, registrable TEXT NOT NULL, brand_id TEXT,
  first_seen_at TEXT NOT NULL, found_by TEXT NOT NULL, last_seen_at TEXT, state TEXT, risk_score REAL,
  coverage REAL, last_assessed_at TEXT, data_mode TEXT NOT NULL DEFAULT 'LIVE'
);
CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL REFERENCES domains(id), url TEXT NOT NULL UNIQUE,
  first_seen_at TEXT NOT NULL, source TEXT NOT NULL, data_mode TEXT NOT NULL DEFAULT 'LIVE'
);
CREATE TABLE IF NOT EXISTS facts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL REFERENCES domains(id), type TEXT NOT NULL,
  value_json TEXT NOT NULL, source TEXT NOT NULL, observed_at TEXT, fetched_at TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('ok','missing','error')), error TEXT,
  data_mode TEXT NOT NULL DEFAULT 'LIVE', raw_ref TEXT, job_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_facts_domain_type ON facts(domain_id, type, fetched_at);
CREATE TABLE IF NOT EXISTS feed_index (
  domain TEXT PRIMARY KEY, sources TEXT NOT NULL, first_listed_at TEXT, last_listed_at TEXT
);
CREATE TABLE IF NOT EXISTS feed_meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, class TEXT NOT NULL DEFAULT 'light', target TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}', priority INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','done','failed','partial')),
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3, run_after TEXT,
  started_at TEXT, finished_at TEXT, error TEXT, idem_key TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_jobs_claim ON jobs(status, class, run_after);
CREATE INDEX IF NOT EXISTS idx_jobs_target ON jobs(target, kind, status);  -- db.current_facts per domain (graph.load on every assessment): 0.41 -> 0.07 s on a large database
CREATE TABLE IF NOT EXISTS cursors (connector TEXT PRIMARY KEY, cursor TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS assessments (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL REFERENCES domains(id), rule_version TEXT NOT NULL,
  risk_score REAL NOT NULL, coverage REAL NOT NULL, state TEXT NOT NULL, flags_json TEXT NOT NULL,
  components_json TEXT NOT NULL, evidence_ids_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS edges (
  id INTEGER PRIMARY KEY AUTOINCREMENT, a_domain_id INTEGER NOT NULL REFERENCES domains(id),
  b_domain_id INTEGER NOT NULL REFERENCES domains(id), feature TEXT NOT NULL, shared_value TEXT NOT NULL,
  rarity REAL NOT NULL, strength REAL NOT NULL, sentence TEXT NOT NULL, evidence_ids_json TEXT NOT NULL,
  first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, rule_version TEXT NOT NULL,
  CHECK (a_domain_id < b_domain_id), UNIQUE (a_domain_id, b_domain_id, feature, shared_value)
);
CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL REFERENCES domains(id),
  kind TEXT NOT NULL CHECK (kind IN ('screenshot','html_gz','visible_text','redirect_chain')),
  path TEXT NOT NULL, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL, captured_at TEXT NOT NULL,
  data_mode TEXT NOT NULL DEFAULT 'LIVE'
);
CREATE TABLE IF NOT EXISTS explanations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL REFERENCES domains(id),
  assessment_id INTEGER NOT NULL REFERENCES assessments(id), model TEXT NOT NULL, prompt_version TEXT NOT NULL,
  output_json TEXT, valid INTEGER NOT NULL DEFAULT 0, error TEXT, input_tokens INTEGER, output_tokens INTEGER,
  trigger TEXT NOT NULL CHECK (trigger IN ('manual_check','auto_top','click')), created_at TEXT NOT NULL,
  input_hash TEXT, carried_from INTEGER REFERENCES explanations(id), fact_order TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_explanations_valid ON explanations(assessment_id) WHERE valid = 1;
CREATE TABLE IF NOT EXISTS llm_spend (
  day TEXT PRIMARY KEY, calls INTEGER NOT NULL DEFAULT 0, input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0, est_usd REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS budgets (
  source TEXT NOT NULL, pool TEXT NOT NULL CHECK (pool IN ('manual','auto')), window_start TEXT NOT NULL,
  used INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (source, pool, window_start)
);
CREATE TABLE IF NOT EXISTS search_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, query TEXT NOT NULL, connector TEXT NOT NULL, run_at TEXT NOT NULL,
  status TEXT NOT NULL, result_count INTEGER, error TEXT
);
CREATE TABLE IF NOT EXISTS search_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES search_runs(id), rank INTEGER NOT NULL,
  url TEXT NOT NULL, domain_id INTEGER REFERENCES domains(id), is_official INTEGER NOT NULL DEFAULT 0, title TEXT,
  fetched_at TEXT NOT NULL, data_mode TEXT NOT NULL DEFAULT 'LIVE'
);
CREATE TABLE IF NOT EXISTS feedback (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL REFERENCES domains(id),
  assessment_id INTEGER REFERENCES assessments(id),
  verdict TEXT NOT NULL CHECK (verdict IN ('scam','legit','unclear')), reason TEXT NOT NULL,
  analyst TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS heartbeats (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, loop TEXT NOT NULL, ok INTEGER NOT NULL DEFAULT 1,
  entries INTEGER, tree_size INTEGER, skipped INTEGER, candidates INTEGER, lag_s INTEGER, error TEXT, cursor INTEGER
);
CREATE INDEX IF NOT EXISTS idx_heartbeats_loop ON heartbeats(loop, at);
CREATE TABLE IF NOT EXISTS ai_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain_id INTEGER NOT NULL REFERENCES domains(id),
  assessment_id INTEGER NOT NULL REFERENCES assessments(id), role TEXT NOT NULL CHECK (role IN ('judge')),
  model TEXT NOT NULL, prompt_version TEXT NOT NULL, output_json TEXT, valid INTEGER NOT NULL DEFAULT 0, error TEXT,
  input_tokens INTEGER, output_tokens INTEGER, est_usd REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
  input_hash TEXT, carried_from INTEGER REFERENCES ai_reviews(id)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_reviews_once ON ai_reviews(assessment_id, role);
CREATE INDEX IF NOT EXISTS idx_ai_reviews_day ON ai_reviews(role, created_at);
CREATE INDEX IF NOT EXISTS idx_assessments_domain ON assessments(domain_id, id);  -- latest assessment per domain: queue 270->11 ms, health 382->61 ms
