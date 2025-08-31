#!/usr/bin/env bash
# Drop ALL data and schema from Dgraph so deployschema.sh can re-apply cleanly.
# Usage:
#   DGRAPH_URL=http://localhost:8080 ./delete_data.sh
# Options:
#   DRY_RUN=1         Show the request that would be sent, do not perform drop
#   CURL_OPTS=...     Additional curl options (e.g., -u user:pass, -H 'Auth: ...')
#   ALTER_ENDPOINT    Override (defaults to "$DGRAPH_URL/alter")
#   CONFIRM=1         Skip interactive confirmation

set -euo pipefail

# Resolve script directory (for parity with other scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Config
DGRAPH_URL="${DGRAPH_URL:-http://localhost:8080}"
ALTER_ENDPOINT="${ALTER_ENDPOINT:-${DGRAPH_URL%/}/alter}"
DRY_RUN="${DRY_RUN:-0}"
CURL_OPTS=${CURL_OPTS:-}

log() { printf "[%s] %s\n" "$(date +"%Y-%m-%dT%H:%M:%S%z")" "$*"; }
err() { printf "[ERROR] %s\n" "$*" 1>&2; }
require_bin() { command -v "$1" >/dev/null 2>&1 || { err "Required binary '$1' not found in PATH"; exit 1; }; }

confirm_or_exit() {
  if [[ "${CONFIRM:-0}" == "1" ]]; then return 0; fi
  echo "DANGER: This will DROP ALL DATA AND SCHEMA in the target Dgraph instance:" 1>&2
  echo "        ${ALTER_ENDPOINT}" 1>&2
  read -r -p "Type 'drop all' to proceed: " ans
  if [[ "$ans" != "drop all" ]]; then
    err "Aborted by user"
    exit 1
  fi
}

main() {
  require_bin curl

  log "DGRAPH_URL=${DGRAPH_URL}"
  log "ALTER_ENDPOINT=${ALTER_ENDPOINT}"

  # Dgraph drop-all operation
  DROP_PAYLOAD='{"drop_all": true}'

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "----- DRY RUN: Drop all payload -----"
    echo "$DROP_PAYLOAD" | sed -e 's/^/    /'
    echo "POST ${ALTER_ENDPOINT} (Content-Type: application/json)"
    echo "----- END DRY RUN -----"
    exit 0
  fi

  confirm_or_exit

  tmp_resp=$(mktemp)
  http_code=$(curl -sS -o "$tmp_resp" -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    --data-binary "$DROP_PAYLOAD" \
    ${CURL_OPTS} \
    "$ALTER_ENDPOINT" || true)

  if [[ "$http_code" =~ ^2 ]]; then
    log "Drop all succeeded (${http_code})."
    # Optionally show compact response
    sed -e 's/^/[resp] /' "$tmp_resp"
    rm -f "$tmp_resp"
  else
    err "Drop all failed (${http_code}). Response:"
    sed -e 's/^/    /' "$tmp_resp" 1>&2
    rm -f "$tmp_resp"
    exit 1
  fi
}

main "$@"
