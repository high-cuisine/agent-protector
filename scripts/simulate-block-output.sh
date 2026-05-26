#!/usr/bin/env bash
#
# Симуляция «живой» работы protector: INFO/DEBUG строки и панели BLOCKED/WARNING
# как в protector/src/reporter.rs.
#
#   PROTECTOR_SIM_STEP    — сек. между основными шагами (по умолчанию 1.4)
#   PROTECTOR_SIM_MICRO   — сек. между двумя DEBUG в одном пакете (по умолчанию 0.4)
#   NO_COLOR=1            — без ANSI
#
# Запуск:
#   ./simulate-block-output.sh                 # тур из 10 крупных этапов (с паузами)
#   QUICK=1 ./simulate-block-output.sh quick # без задержек
#   ./simulate-block-output.sh secret [pid]
#   ./simulate-block-output.sh sql

set -euo pipefail

STEP="${PROTECTOR_SIM_STEP:-1.4}"
MICRO="${PROTECTOR_SIM_MICRO:-0.4}"

if [[ "${NO_COLOR:-}" == "1" || "${TERM:-}" == "dumb" ]]; then
  USE_COLOR=0
else
  USE_COLOR=1
fi

if [[ "$USE_COLOR" == 1 ]]; then
  RS=$'\033[0m'
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  RED=$'\033[38;2;210;55;55m'
  YELLOW=$'\033[38;2;220;185;40m'
  CYAN=$'\033[38;2;80;200;200m'
  GREEN=$'\033[38;2;140;210;140m'
else
  RS="" BOLD="" DIM="" RED="" YELLOW="" CYAN="" GREEN=""
fi

readonly MINI=(
  "..RRRR.."
  ".DMMMMM."
  ".DMDMMD."
  ".DKKKKKD"
  ".DMMMMMD"
  "NDDDDDDN"
  "NDDKKDDN"
  ".DD..DD."
)

sleep_maybe() {
  [[ "${QUICK:-0}" == 1 ]] && return 0
  sleep "$@"
}

pause_step() {
  sleep_maybe "$STEP"
}

pause_micro() {
  sleep_maybe "$MICRO"
}

c_knight() {
  local ch="$1"
  [[ "$USE_COLOR" == 0 ]] && return 0
  case "$ch" in
    K) printf '\033[38;2;15;15;15m' ;;
    D) printf '\033[38;2;26;74;74m' ;;
    M) printf '\033[38;2;42;110;110m' ;;
    R) printf '\033[38;2;176;32;32m' ;;
    N) printf '\033[38;2;212;168;112m' ;;
    *) ;;
  esac
}

render_knight_row() {
  local row="$1" out="" cur="" i ch
  for ((i = 0; i < ${#row}; i++)); do
    ch=${row:i:1}
    if [[ "$ch" == '.' ]]; then
      out+="${RS}"
      cur=""
      out+="  "
    else
      if [[ "$cur" != "$ch" ]]; then
        out+="${RS}"
        out+="$(c_knight "$ch")"
        cur=$ch
      fi
      out+="██"
    fi
  done
  out+="${RS}"
  printf '%s' "$out"
}

clip_str() {
  local s="$1" max="$2" out
  if ((${#s} <= max)); then printf '%s' "$s"; return 0; fi
  out="$(printf '%s' "$s" | awk -v n="$max" '{print substr($0, 1, n)}')"
  printf '%s' "$out"
}

fill_detail_clip() {
  local text="$1" max_clip="${2:-52}"
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    trimmed="$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' <<<"$line")"
    [[ -z "$trimmed" ]] && continue
    printf '%s\n' "$(clip_str "$trimmed" "$max_clip")"
  done <<<"$text"
}

# level: blocked | warning
emit_report_panel() {
  local level="$1"
  shift
  local action="$1" pid="$2" ts="$3" cmd="$4" code="$5" detail_text="$6"

  local accent icon headline
  if [[ "$level" == "blocked" ]]; then
    headline="BLOCKED"
    icon="⚔  "
    accent="$RED"
  else
    headline="WARNING"
    icon="⚠  "
    accent="$YELLOW"
  fi

  local bar=""
  local i_bar
  for ((i_bar = 0; i_bar < 66; i_bar++)); do bar+="─"; done
  if [[ "$USE_COLOR" == 1 ]]; then
    bar="${accent}  ${bar}${RS}"
  else
    bar="  ${bar}"
  fi

  local _buf d_lines=()
  _buf="$(fill_detail_clip "$detail_text" 52 || true)"
  while IFS= read -r _ln || [[ -n "${_ln:-}" ]]; do
    [[ -z "${_ln:-}" ]] && continue
    d_lines+=("$_ln")
  done <<<"$_buf"

  local sep=""
  local j
  for ((j = 0; j < 48; j++)); do sep+="─"; done
  [[ "$USE_COLOR" == 1 ]] && sep="${DIM}${sep}${RS}"

  local line0 line1 line2
  if [[ "$USE_COLOR" == 1 ]]; then
    line0="${accent}${BOLD}${icon}${headline}${RS}  ${CYAN}${action}${RS}  ${DIM}[${code}]${RS}"
    line1="${DIM}pid=${pid}   ${ts}${RS}"
    line2="${DIM}cmd:${RS} $(clip_str "$cmd" 46)"
  else
    line0="${icon}${headline}  ${action}  [${code}]"
    line1="pid=${pid}   ${ts}"
    line2="cmd: $(clip_str "$cmd" 46)"
  fi

  local lbl0="${d_lines[0]:-}" lbl1="${d_lines[1]:-}" lbl2="${d_lines[2]:-}"

  local footer_txt footer_hint
  if [[ "$level" == "blocked" ]]; then
    footer_txt='Итог: SIGKILL дочернему процессу. Журнал: $PROTECTOR_REPORT_DIR или /tmp/protector'
  else
    footer_txt="Предупреждение в отчёт; процесс продолжается после SIGCONT"
  fi
  if [[ "$USE_COLOR" == 1 ]]; then
    footer_hint="${DIM}${footer_txt}${RS}"
  else
    footer_hint="$footer_txt"
  fi

  printf '\n%s\n' "$bar" >&2
  local i rk
  for i in "${!MINI[@]}"; do
    rk=$(render_knight_row "${MINI[i]}")
    case $i in
      0) printf '  %s   %s\n' "$rk" "$line0" >&2 ;;
      1) printf '  %s   %s\n' "$rk" "$line1" >&2 ;;
      2) printf '  %s   %s\n' "$rk" "$line2" >&2 ;;
      3) printf '  %s   %s\n' "$rk" "$sep" >&2 ;;
      4) printf '  %s   %s\n' "$rk" "$lbl0" >&2 ;;
      5) printf '  %s   %s\n' "$rk" "$lbl1" >&2 ;;
      6) printf '  %s   %s\n' "$rk" "$lbl2" >&2 ;;
      7) printf '  %s   %s\n' "$rk" "$footer_hint" >&2 ;;
    esac
  done
  printf '%s\n\n' "$bar" >&2
}

intercept_info() {
  local pid="$1" tool="$2" args_human="$3"
  printf '[INFO  protector] Agent action intercepted: pid=%s tool=%s args=%s\n' "$pid" "$tool" "$args_human" >&2
}

log_debug_skip() {
  printf '[DEBUG protector] skip pid=%s file=%s comm=%s args=%s reason=%s\n' "${1:?}" "${2:?}" "${3:?}" "${4:-[]}" "${5:?}" >&2
}

log_info_plain() {
  printf '[INFO  protector] %s\n' "${1:?}" >&2
}

allow_line() {
  printf '[INFO  protector] [%s] ALLOWED — resuming pid=%s\n' "${1:?}" "${2:?}" >&2
}

# ── 10 крупных этапов тура ────────────────────────────────────────────────────

stage_01_boot() {
  log_info_plain 'Protector started — monitoring Claude Code agent actions (RUST_LOG=debug for skip reasons)'
  pause_micro
  local rd="${PROTECTOR_REPORT_DIR:-/tmp/protector}"
  log_info_plain "reporter: block reports → ${rd}"
}

stage_02_claude() {
  log_info_plain 'Claude/Code root PIDs (watching descendants): [7049, 7381]'
}

stage_03_skips() {
  log_debug_skip 7360 "/usr/bin/node" "npm" '["npm", "audit"]' "not_in_tool_watchlist"
  pause_micro
  log_debug_skip 7435 '/usr/bin/git' 'claude' '["git", "-c", "...", "ls-files"]' \
    'no_matching_tool_rule (argv does not match any ToolDb action)'
}

stage_04_allow_git() {
  local pid=7701 ts
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  intercept_info "$pid" "git-commit" '["git", "commit", "-m", "docs only"]'
  pause_micro
  allow_line "git-commit" "$pid"
  log_info_plain "[git-commit] pid=${pid} — no secrets found, allowing"
}

stage_05_warn_sql() {
  local pid=7720 ts txt
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  intercept_info "$pid" "psql" '["psql", "-c", "SELECT * FROM information_schema.tables LIMIT 10;"]'
  pause_micro
  txt="$(cat <<'TXT'
[SQL_SUSPICIOUS] psql: 1 suspicious pattern(s) — proceeding with warning:
  ⚠ INFORMATION_SCHEMA breadth query
  Review the query intent before continuing.
TXT
)"
  emit_report_panel "warning" "psql" "$pid" "$ts" \
    'psql -c SELECT … information_schema …' 'SQL_SUSPICIOUS' "$txt"
}

stage_06_block_git_secret() {
  local pid="${1:-7458}" ts txt
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  intercept_info "$pid" "git-commit" '["git", "commit", "-m", "add secrets"]'
  pause_micro
  txt="$(cat <<'TXT'
[SECRET_LEAK] 4 credential(s) detected in staged file(s) — commit blocked:
  secrets.env:1 · AWS Access Key ID → AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
  secrets.env:2 · AWS Secret Access Key → AWS_SECRET_ACCESS_KEY=wJalr…EXAMPLEKEY
  secrets.env:4 · Generic API Key → API_KEY=sk-1234567890abcdef1234567890abcdef
  secrets.env:5 · GitHub Token (classic) → GITHUB_TOKEN=ghp_123456789abcdef…
  Remove or rotate the credentials before committing.
TXT
)"
  emit_report_panel "blocked" "git-commit" "$pid" "$ts" \
    'git commit -m add secrets' 'SECRET_LEAK' "$txt"
}

stage_07_block_psql() {
  local pid=7512 ts txt
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  intercept_info "$pid" "psql" '["psql", "-c", "DROP TABLE payments;"]'
  pause_micro
  txt="$(cat <<'TXT'
[SQL_DESTRUCTIVE] psql: 1 irreversible operation(s) blocked:
  • DROP TABLE
  Use a targeted WHERE clause or coordinate with the DBA.
TXT
)"
  emit_report_panel "blocked" "psql" "$pid" "$ts" \
    'psql -c DROP TABLE payments;' 'SQL_DESTRUCTIVE' "$txt"
}

stage_08_block_mysql_inj() {
  local pid=7533 ts txt
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  intercept_info "$pid" "mysql" '["mysql", "-e", "SELECT 1 UNION SELECT password FROM admins;"]'
  pause_micro
  txt="$(cat <<'TXT'
[SQL_INJECTION] mysql: 1 injection pattern(s) detected — blocked:
  • UNION-based second SELECT
  Use parameterised queries instead of interpolated SQL.
TXT
)"
  emit_report_panel "blocked" "mysql" "$pid" "$ts" \
    'mysql -e SELECT 1 UNION…' 'SQL_INJECTION' "$txt"
}

stage_09_block_docker() {
  local pid=7601 ts txt
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  intercept_info "$pid" "docker" '["docker", "run", "--privileged", "evil:latest"]'
  pause_micro
  txt="$(cat <<'TXT'
[DOCKER_UNSAFE_RUN] docker run: 1 dangerous configuration issue(s) — blocked:
  • --privileged grants full host capabilities
  Remove the unsafe flags or switch to a least-privilege configuration.
TXT
)"
  emit_report_panel "blocked" "docker" "$pid" "$ts" \
    'docker run --privileged evil:latest' 'DOCKER_UNSAFE_RUN' "$txt"
}

stage_10_block_redis() {
  local pid=7618 ts txt
  ts=$(date +"%Y-%m-%d %H:%M:%S")
  intercept_info "$pid" "redis-cli" '["redis-cli", "FLUSHALL"]'
  pause_micro
  txt="$(cat <<'TXT'
[REDIS_DESTRUCTIVE] redis-cli FLUSHALL: wipes ALL keys on ALL logical DBs — blocked.
TXT
)"
  emit_report_panel "blocked" "redis-cli" "$pid" "$ts" \
    'redis-cli FLUSHALL' 'REDIS_DESTRUCTIVE' "$txt"
  pause_micro
  log_info_plain "Shutting down protector (демо-тур завершён; Ctrl+C в реальной работе)."
}

run_full_demo() {
  QUICK="${QUICK:-0}"
  

  stage_01_boot && pause_step
  stage_02_claude && pause_step
  stage_03_skips && pause_step
  stage_04_allow_git && pause_step
  stage_05_warn_sql && pause_step
  stage_06_block_git_secret "${1:-}" && pause_step
  stage_07_block_psql && pause_step
  stage_08_block_mysql_inj && pause_step
  stage_09_block_docker && pause_step
  stage_10_block_redis
}

only_secret_demo() {
  QUICK="${QUICK:-0}"
  stage_06_block_git_secret "${1:-7458}"
}

only_sql_demo() {
  QUICK="${QUICK:-0}"
  stage_07_block_psql
}

help() {
  cat >&2 <<'H'
simulate-block-output.sh

  По умолчанию — тур из 10 этапов со sleep между ними.

  Переменные:
    PROTECTOR_SIM_STEP  пауза между этапами (сек), по умолчанию 1.4
    PROTECTOR_SIM_MICRO паузы внутри этапов (редко), по умолчанию 0.4
    QUICK=1 или ./simulate-block-output.sh quick — без паузы

Примеры:
  ./simulate-block-output.sh
  PROTECTOR_SIM_STEP=2.2 ./simulate-block-output.sh
  QUICK=1 ./simulate-block-output.sh quick
  ./simulate-block-output.sh secret
  ./simulate-block-output.sh sql
H
}

main() {
  case "${1:-}" in
    -h|--help|help) help ;;
    quick)
      shift || true
      QUICK=1
      run_full_demo "${@:-}"
      ;;
    secret) only_secret_demo "${2:-7458}" ;;
    sql)    only_sql_demo ;;
    *)      run_full_demo "${@:-}" ;;
  esac
}

if [[ "${PROTECTOR_SIM_LIB_ONLY:-}" != 1 ]]; then
  main "$@"
fi
