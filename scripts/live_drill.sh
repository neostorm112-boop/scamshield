#!/usr/bin/env bash
# Live drill (R6): run ./run.sh on a clean data dir against live CT logs, log stats every 60 s,
# at minute KILL_MIN submit a manual check, kill -9 the app while that job is running, restart, verify the job finished
# and no duplicate facts. Ends with the CT findings. Usage: scripts/live_drill.sh [DURATION_MIN=30 (1..1440)] [KILL_MIN=10]
# Prints PASS or FAIL (exit 0 / 1).
set -uo pipefail
cd "$(dirname "$0")/.."
DURATION_MIN="${1:-30}"
KILL_MIN="${2:-10}"
case "$DURATION_MIN" in ''|*[!0-9]*) echo "FAIL: duration must be whole minutes"; exit 1 ;; esac
[ "$DURATION_MIN" -ge 1 ] && [ "$DURATION_MIN" -le 1440 ] || { echo "FAIL: duration must be 1..1440 minutes"; exit 1; }
export PORT="${PORT:-8765}"
export SCAMSHIELD_DATA_DIR="${SCAMSHIELD_DATA_DIR:-$(mktemp -d)}"
mkdir -p "$SCAMSHIELD_DATA_DIR"
[ -e "$SCAMSHIELD_DATA_DIR/scamshield.db" ] && { echo "FAIL: $SCAMSHIELD_DATA_DIR is not clean"; exit 1; }
DB="$SCAMSHIELD_DATA_DIR/scamshield.db"
LOG="$SCAMSHIELD_DATA_DIR/drill.log"
BASE="http://127.0.0.1:$PORT"
PID=""
DRILL_URL="https://www.rta.ae"
DRILL_HOST="www.rta.ae"

say() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$LOG"; }
q() { sqlite3 -separator ' ' "$DB" "$1" 2>/dev/null; }

start_app() {
  ./run.sh >>"$SCAMSHIELD_DATA_DIR/app.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 90); do
    curl -fs -o /dev/null "$BASE/" && return 0
    sleep 1
  done
  say "app did not start within 90 s"; return 1
}

stop_app() { [ -n "$PID" ] && kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; true; }
trap stop_app EXIT

dups() {
  q "SELECT COUNT(*) FROM (SELECT 1 FROM facts GROUP BY domain_id, type, source, job_id, value_json HAVING COUNT(*) > 1)"
}

sample() {
  q "SELECT substr(key,4), COALESCE(json_extract(value,'\$.lag_entries'),'-'), COALESCE(json_extract(value,'\$.lag_minutes'),'-'),
            COALESCE(round((json_extract(value,'\$.samples[#-1][1]') - json_extract(value,'\$.samples[0][1]')) * 1.0
                 / NULLIF(json_extract(value,'\$.samples[#-1][0]') - json_extract(value,'\$.samples[0][0]'), 0), 1), '-')
     FROM feed_meta WHERE key LIKE 'ct:%'" | while read -r log lag_e lag_m rate; do
    say "log=$log rate=${rate}/s lag=${lag_e} entries (${lag_m} min)"
  done
  say "domains=$(q 'SELECT COUNT(*) FROM domains') jobs=[$(q "SELECT group_concat(status || ':' || n, ' ') FROM (SELECT status, COUNT(*) n FROM jobs GROUP BY status)")] duplicate_facts=$(dups)"
  q "SELECT name, status FROM sources WHERE status != 'ok'" | while read -r line; do say "source not ok: $line"; done
}

FAILS=()
: >"$LOG"
say "drill start: duration=${DURATION_MIN} min, kill at minute ${KILL_MIN}, data=$SCAMSHIELD_DATA_DIR, port=$PORT"
start_app || { echo "FAIL: app did not start"; exit 1; }

for minute in $(seq 1 "$DURATION_MIN"); do
  sleep 60
  say "minute $minute"
  sample
  if [ "$minute" -eq "$KILL_MIN" ]; then
    curl -s -o /dev/null --data-urlencode "url=$DRILL_URL" "$BASE/check"
    running=""
    for _ in $(seq 1 400); do  # the running window is short: poll often
      [ "$(q "SELECT status FROM jobs WHERE target = '$DRILL_HOST' ORDER BY id DESC LIMIT 1")" = "running" ] && { running=1; break; }
      sleep 0.05
    done
    before="$(q "SELECT status FROM jobs WHERE target = '$DRILL_HOST' ORDER BY id DESC LIMIT 1")"
    kill -9 "$PID"; wait "$PID" 2>/dev/null
    say "kill -9 of the app after manual check of $DRILL_HOST; job status before kill: ${before:-none}"
    [ -n "$running" ] || { FAILS+=("manual job never reached running within 20 s (last status=${before:-none}); kill was not mid-job"); break; }
    start_app || { FAILS+=("restart failed"); break; }
    status=""
    for _ in $(seq 1 90); do
      status="$(q "SELECT status FROM jobs WHERE target = '$DRILL_HOST' ORDER BY id DESC LIMIT 1")"
      case "$status" in done|partial|failed) break ;; esac
      sleep 1
    done
    say "after restart: job $DRILL_HOST = ${status:-none}, duplicate_facts=$(dups)"
    case "$status" in done|partial) ;; *) FAILS+=("manual job not finished after restart (status=${status:-none})") ;; esac
  fi
done

kill -0 "$PID" 2>/dev/null || FAILS+=("app is not running at the end")
[ "$(dups)" = "0" ] || FAILS+=("duplicate facts: $(dups)")
[ "$KILL_MIN" -le "$DURATION_MIN" ] || FAILS+=("kill minute is after the end of the drill")
# lag must not be growing: a log still behind the amber threshold at the end is a failure
late="$(q "SELECT substr(key,4) FROM feed_meta WHERE key LIKE 'ct:%' AND json_extract(value,'\$.lag_minutes') > 5")"
[ -z "$late" ] || FAILS+=("lag over 5 min at the end: $late")

say "CT findings: $(q "SELECT COUNT(*) FROM domains WHERE found_by = 'ct_tiled'")"
q "SELECT fqdn FROM domains WHERE found_by = 'ct_tiled' ORDER BY id" | while read -r fqdn; do say "  ct: $fqdn"; done

if [ "${#FAILS[@]}" -eq 0 ]; then
  say "PASS"; exit 0
fi
say "FAIL: $(printf '%s; ' "${FAILS[@]}")"; exit 1
