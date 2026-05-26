#!/usr/bin/env bash
#
# Транскрипт shell-сессии (stderr): успешный commit с секретами в репозитории.
#
#   ./simulate-agent-commits-secrets.sh
#   QUICK=1 ./simulate-agent-commits-secrets.sh
#   PROTECTOR_AGENT_PAUSE=0.5
#   NO_COLOR=1 ...

set -euo pipefail

PAUSE="${PROTECTOR_AGENT_PAUSE:-0.7}"
SHORT="${PROTECTOR_AGENT_PAUSE_SHORT:-0.2}"

if [[ "${NO_COLOR:-}" == "1" || "${TERM:-}" == "dumb" ]]; then
  RS="" DIM="" BOLD="" GRN="" MAG="" GLY=""
else
  RS=$'\033[0m'
  DIM=$'\033[2m'
  BOLD=$'\033[1m'
  GRN=$'\033[32m'
  MAG=$'\033[35m'
  GLY=$'\033[38;5;246m'
fi

Z() {
  [[ "${QUICK:-0}" == 1 ]] && return 0
  sleep "${1:?}"
}

cmd() {
  printf '%s$ %s\n' "${GRN}" "${1:?}" >&2
  Z "$PAUSE"
}

out() {
  printf '%s%s\n' "${GLY}${DIM}" "${1-}" >&2
  Z "${2:-$SHORT}"
}

run() {

  printf '\n%suser@msk-dev:~/project/agent-demo%s\n' "${DIM}${BOLD}" "${RS}" >&2
  cmd 'pwd'
  out '/home/user/project/agent-demo'

  cmd 'cat >> secrets.env <<'\''EOF'\''
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
API_KEY=sk-1234567890abcdef1234567890abcdef
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
EOF'
  out ''

  cmd 'git add secrets.env'
  cmd 'git status --short secrets.env'
  out 'A  secrets.env'

  cmd 'git commit -m "chore: add env example for staging"'

  out '' "$PAUSE"

  printf '%s[master a4f29c8]%s chore: add env example for staging\n' "${MAG}${BOLD}" "${RS}" >&2
  out ' 1 file changed, 4 insertions(+)'

  cmd 'git log -1 --oneline'
  printf '%s%s%s chore: add env example for staging\n' "${GLY}${DIM}" "a4f29c8" "${RS}" >&2
  Z "$PAUSE"

  printf '\n' >&2
}

case "${1:-}" in
  -h|--help)
    sed -n '1,12p' "$0" >&2
    ;;
  *)
    run
    ;;
esac
