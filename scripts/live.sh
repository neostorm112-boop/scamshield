#!/usr/bin/env bash
# Live run launcher.
#   scripts/live.sh start <name> <port>   fresh or continued run in data/runs/<name>; app + watchdog survive a closed terminal
#   scripts/live.sh status <name>         one block from /healthz
#   scripts/live.sh stop <name>           stop watchdog, then the app
#   scripts/live.sh report <name>         effectiveness report -> docs/evidence/live-<name>.md
set -o pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
CMD="${1:-}"; NAME="${2:-}"; PORT="${3:-}"
INTERVAL="${WATCHDOG_INTERVAL:-30}"
CT_PROBE="https://mon.willow.ct.letsencrypt.org/2026h2/checkpoint"
refuse() { echo "refused: $*" >&2; exit 1; }
[[ "$NAME" =~ ^[A-Za-z0-9_-]+$ ]] || refuse "run name must be letters, digits, - or _"
[ "$NAME" != "day1" ] || refuse "day1 is a frozen run"
DIR="$ROOT/data/runs/$NAME"
[ -z "$PORT" ] && [ -f "$DIR/port" ] && PORT="$(cat "$DIR/port")"
if [ "$CMD" = start ] || [ "$CMD" = _watchdog ]; then
  [[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || refuse "port must be 1024..65535"
  { [ "$PORT" = 8765 ] || [ "$PORT" = 8766 ]; } && refuse "ports 8765 and 8766 belong to other runs"
fi
log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }

setup_env() {
  export SCAMSHIELD_LIVE=1 SCAMSHIELD_DATA_DIR="$DIR" PORT
  # run.sh reads ./.env; a worktree has none, so fall back to the main checkout's (values are never printed)
  if [ ! -f "$ROOT/.env" ]; then
    local main; main="$(git worktree list --porcelain | sed -n '1s/^worktree //p')"
    [ -f "$main/.env" ] && { set -a; . "$main/.env"; set +a; }
  fi
}

app_pid() { local pid; pid="$(cat "$DIR/live.pid" 2>/dev/null)"; [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && echo "$pid"; }

launch_app() {
  nohup ./run.sh >>"$DIR/app.log" 2>&1 </dev/null &
  local pid=$!
  echo "$pid" >"$DIR/live.pid"
  nohup caffeinate -dimsu -w "$pid" >/dev/null 2>&1 &  # follows the app: sleep is blocked only while it lives
}

stop_app() {
  local pid; pid="$(app_pid)" || return 0
  ps -p "$pid" -o command= | grep -q -e uvicorn -e run.sh || return 0  # pid reused by something else: never touch it
  kill -TERM "$pid" 2>/dev/null
  for _ in $(seq 1 15); do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
  kill -KILL "$pid" 2>/dev/null
}

healthz() { curl -fs -m 5 "http://127.0.0.1:$PORT/healthz"; }

watchdog() {
  setup_env
  local fails=0 recent="" last_try=0 n=0 prev; prev="$(date +%s)"
  log "watchdog start: port=$PORT interval=${INTERVAL}s"
  while :; do
    sleep "$INTERVAL"
    local now reason="" body age ct_age; now="$(date +%s)"
    if [ $((now - prev)) -gt $((INTERVAL * 3)) ]; then  # we slept too: the machine was paused, do not blame the app
      log "machine pause detected: $((now - prev)) s without a watchdog tick"; prev="$now"; fails=0; continue
    fi
    prev="$now"; n=$((n + 1))
    if ! app_pid >/dev/null; then reason="process dead"
    elif body="$(healthz)"; then
      fails=0
      age="$(echo "$body" | .venv/bin/python -c 'import sys,json; print(json.load(sys.stdin).get("worker_age_s") or 0)' 2>/dev/null)"
      ct_age="$(echo "$body" | .venv/bin/python -c 'import sys,json; print(json.load(sys.stdin).get("ct_age_s") or 0)' 2>/dev/null)"
      if [ $((now - last_try)) -gt 300 ]; then  # a fresh process needs time for its first beats: the ages still come from the old one (3 restarts in 62 s)
        [ "${age:-0}" -gt 300 ] && reason="worker heartbeat ${age}s old"
        [ "${ct_age:-0}" -gt 300 ] && reason="CT loops heartbeat ${ct_age}s old${reason:+; $reason}"
      fi
    else
      fails=$((fails + 1)); [ "$fails" -ge 3 ] && reason="healthz failed 3 times"
    fi
    if [ $((n * INTERVAL % 300)) -eq 0 ]; then log "status: pid=$(cat "$DIR/live.pid" 2>/dev/null) fails=$fails restarts_last_hour=$(echo "$recent" | wc -w | tr -d ' ')"; fi
    [ -n "$reason" ] || continue
    recent="$(for t in $recent; do [ $((now - t)) -lt 3600 ] && echo "$t"; done)"
    # after 5 restarts in an hour do not give up: one attempt every 15 min
    if [ "$(echo "$recent" | wc -w | tr -d ' ')" -ge 5 ] && [ $((now - last_try)) -lt 900 ]; then continue; fi
    printf '%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$reason" >>"$DIR/restarts.log"
    log "restart: $reason"
    stop_app; launch_app
    recent="$recent $now"; last_try="$now"; fails=0
  done
}

case "$CMD" in
  start)
    app_pid >/dev/null && refuse "run $NAME is already running"
    lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1 && refuse "port $PORT is busy"
    mkdir -p "$DIR"
    if [ -f "$DIR/scamshield.db" ]; then
      [ "$(sqlite3 "$DIR/scamshield.db" "SELECT count(*) FROM domains WHERE data_mode = 'SYNTHETIC'" 2>/dev/null)" = 0 ] || refuse "$DIR holds SYNTHETIC rows"
    fi
    curl -fs -m 5 -o /dev/null "$CT_PROBE" || echo "WARN: CT log did not answer in 5 s; starting anyway (sources will show red)"
    echo "$PORT" >"$DIR/port"
    setup_env
    launch_app
    for _ in $(seq 1 120); do healthz >/dev/null && break; sleep 1; done
    healthz >/dev/null || { stop_app; refuse "app did not answer /healthz in 120 s, see $DIR/app.log"; }
    nohup "$ROOT/scripts/live.sh" _watchdog "$NAME" "$PORT" >>"$DIR/watchdog.log" 2>&1 </dev/null &
    echo $! >"$DIR/watchdog.pid"
    echo "live run $NAME: http://127.0.0.1:$PORT  data=$DIR"
    echo "status: scripts/live.sh status $NAME | stop: scripts/live.sh stop $NAME | report: scripts/live.sh report $NAME"
    ;;
  status)
    echo "run $NAME port=${PORT:-?} app=$(app_pid || echo down) watchdog=$(kill -0 "$(cat "$DIR/watchdog.pid" 2>/dev/null)" 2>/dev/null && echo up || echo down)"
    healthz | .venv/bin/python -c 'import sys,json; h=json.load(sys.stdin); print(h["banner"] and h["banner"]["text"], h["counters"], h["queue"])' || echo "healthz: no answer"
    [ -f "$DIR/restarts.log" ] && echo "restarts: $(wc -l <"$DIR/restarts.log" | tr -d ' ')"
    ;;
  stop)
    kill "$(cat "$DIR/watchdog.pid" 2>/dev/null)" 2>/dev/null; rm -f "$DIR/watchdog.pid"
    stop_app; rm -f "$DIR/live.pid"
    echo "run $NAME stopped"
    ;;
  report)
    .venv/bin/python -m scamshield.tools.effectiveness "$DIR"
    ;;
  _watchdog) watchdog ;;
  *) refuse "usage: scripts/live.sh start <name> <port> | status <name> | stop <name> | report <name>" ;;
esac
