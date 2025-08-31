#!/usr/bin/env bash
# Delete all User nodes and their UserChannels from Dgraph (data only).
# Usage:
#   DGRAPH_URL=http://localhost:8080 ./delete_users.sh
# Options:
#   DRY_RUN=1        Print the upsert-delete payload instead of applying
#   CURL_OPTS=...    Additional curl options (e.g., -u user:pass or auth headers)
#   MUTATE_ENDPOINT  Override (defaults to "$DGRAPH_URL/mutate?commitNow=true")
#   CONFIRM=1        Skip interactive confirmation

set -euo pipefail

# Resolve script directory (not strictly needed here, but kept for parity)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Config
DGRAPH_URL="${DGRAPH_URL:-http://localhost:8080}"
MUTATE_ENDPOINT="${MUTATE_ENDPOINT:-${DGRAPH_URL%/}/mutate?commitNow=true}"
DRY_RUN="${DRY_RUN:-0}"
CURL_OPTS=${CURL_OPTS:-}

log() { printf "[%s] %s\n" "$(date +"%Y-%m-%dT%H:%M:%S%z")" "$*"; }
err() { printf "[ERROR] %s\n" "$*" 1>&2; }
require_bin() { command -v "$1" >/dev/null 2>&1 || { err "Required binary '$1' not found in PATH"; exit 1; }; }

confirm_or_exit() {
  if [[ "${CONFIRM:-0}" == "1" ]]; then return 0; fi
  echo "This will DELETE all User and UserChannels nodes." 1>&2
  if [[ ! -t 0 ]]; then
    err "Non-interactive shell detected. Re-run with CONFIRM=1 to proceed."
    exit 1
  fi
  read -r -p "Type 'delete users' to proceed: " ans || true
  if [[ "$ans" != "delete users" ]]; then
    err "Aborted by user"
    exit 1
  fi
}

main() {
  require_bin curl

  log "DGRAPH_URL=${DGRAPH_URL}"
  log "MUTATE_ENDPOINT=${MUTATE_ENDPOINT}"

  # Robust RDF upsert delete. Variables are referenced inside mutation/delete so Dgraph
  # recognizes them as used. This deletes all predicates for matched nodes (wildcard).
  UPSERT_BODY=$(cat <<'RDF'
upsert {
  query {
    U as var(func: type(User))
    U2 as var(func: has(did))
    C as var(func: type(UserChannels))
    C2 as var(func: has(channelKey))
    CU as var(func: type(UserChannels)) @filter(uid_in(user, uid(U)))
  }
  mutation {
    delete {
      uid(U)  *  *  .
      uid(U2) *  *  .
      uid(C)  *  *  .
      uid(C2) *  *  .
      uid(CU) *  *  .
    }
  }
}
RDF
  )

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "----- DRY RUN: Upsert delete payload -----"
    echo "$UPSERT_BODY" | sed -e 's/^/    /'
    echo "----- END DRY RUN -----"
    exit 0
  fi

  confirm_or_exit

  tmp_resp=$(mktemp)
  http_code=$(curl -sS -o "$tmp_resp" -w "%{http_code}" -X POST \
    -H "Content-Type: application/rdf" \
    --data-binary "$UPSERT_BODY" \
    ${CURL_OPTS} \
    "$MUTATE_ENDPOINT" || true)

  if [[ "$http_code" =~ ^2 ]]; then
    log "Delete users request succeeded (${http_code}). Response:"
    sed -e 's/^/    /' "$tmp_resp"
    rm -f "$tmp_resp"
  else
    err "Delete users request failed (${http_code}). Response:"
    sed -e 's/^/    /' "$tmp_resp" 1>&2
    rm -f "$tmp_resp"
    exit 1
  fi
}

main "$@"
