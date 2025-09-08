#!/usr/bin/env bash
# Deploy modular Dgraph schema in a deterministic order.
# Usage:
#   DGRAPH_URL=http://localhost:8080 ./deployschema.sh
# Options:
#   DRY_RUN=1    Print schema files instead of applying
#   CURL_OPTS=... Additional curl options (e.g., -u user:pass)
#   ALTER_ENDPOINT overrides the default "$DGRAPH_URL/alter"

set -euo pipefail

# Resolve script directory
SCHEMA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Config
DGRAPH_URL="${DGRAPH_URL:-http://localhost:8080}"
ALTER_ENDPOINT="${ALTER_ENDPOINT:-${DGRAPH_URL%/}/alter}"
DRY_RUN="${DRY_RUN:-0}"
CURL_OPTS=${CURL_OPTS:-}
ROLE_TENANT_PREFIX="${ROLE_TENANT_PREFIX:-default}"

MODULES=(
  common
  base
  profile
  channels
  auth
  audit
)

log() { printf "[%s] %s\n" "$(date +"%Y-%m-%dT%H:%M:%S%z")" "$*"; }
err() { printf "[ERROR] %s\n" "$*" 1>&2; }

require_bin() {
  command -v "$1" >/dev/null 2>&1 || { err "Required binary '$1' not found in PATH"; exit 1; }
}

apply_file() {
  local file="$1"
  log "Applying schema: ${file}"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "----- DRY RUN: ${file} -----"
    sed -e 's/^/    /' "$file"
    echo "----- END DRY RUN -----"
    return 0
  fi

  local tmp_resp
  tmp_resp=$(mktemp)
  local http_code
  http_code=$(curl -sS -o "$tmp_resp" -w "%{http_code}" -X POST \
    -H "Content-Type: application/dql" \
    --data-binary @"$file" \
    ${CURL_OPTS} \
    "$ALTER_ENDPOINT" || true)

  if [[ "$http_code" =~ ^2 ]]; then
    log "Success (${http_code}): ${file}"
    rm -f "$tmp_resp"
  else
    err "Failed (${http_code}) applying: ${file}"
    err "Response:"; sed -e 's/^/    /' "$tmp_resp" 1>&2
    rm -f "$tmp_resp"
    exit 1
  fi
}

role_exists() {
  local role_key="$1"
  local query_payload
  query_payload=$(cat <<EOF
{"query":"{ q(func: eq(roleKey, \"${role_key}\")) { uid } }"}
EOF
)
  local http_code tmp_resp
  tmp_resp=$(mktemp)
  http_code=$(curl -sS -o "$tmp_resp" -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    --data-binary "${query_payload}" \
    ${CURL_OPTS} \
    "${DGRAPH_URL%/}/query" || true)
  if [[ "$http_code" =~ ^2 ]]; then
    # Compact the JSON to avoid whitespace differences and ensure we check data.q
    # Use fixed-string grep to avoid regex brace parsing issues
    if tr -d ' \n\t' < "$tmp_resp" | grep -F -q '"q":[{'; then
      rm -f "$tmp_resp"; return 0 # exists
    else
      rm -f "$tmp_resp"; return 1 # not found
    fi
  else
    err "Role existence check failed (${http_code}) for ${role_key}"
    sed -e 's/^/    /' "$tmp_resp" 1>&2
    rm -f "$tmp_resp"
    return 2
  fi
}

create_role() {
  local name="$1"
  local role_key="$2"
  local json
  json=$(cat <<EOF
{"set":[{"uid":"_:r","dgraph.type":["Role"],"name":"${name}","roleKey":"${role_key}"}]}
EOF
)
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "----- DRY RUN: create role ${name} (${role_key}) -----"
    echo "$json" | sed -e 's/^/    /'
    echo "----- END DRY RUN -----"
    return 0
  fi
  local http_code tmp_resp
  tmp_resp=$(mktemp)
  http_code=$(curl -sS -o "$tmp_resp" -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    --data-binary "$json" \
    ${CURL_OPTS} \
    "${DGRAPH_URL%/}/mutate?commitNow=true" || true)
  if [[ "$http_code" =~ ^2 ]]; then
    if grep -q '"errors"' "$tmp_resp"; then
      err "Mutation reported errors for role: ${name} (${role_key})"
      err "Response:"; sed -e 's/^/    /' "$tmp_resp" 1>&2
      rm -f "$tmp_resp"
      return 1
    fi
    log "Created role: ${name} (${role_key})"
    rm -f "$tmp_resp"
  else
    err "Failed (${http_code}) to create role: ${name} (${role_key})"
    err "Response:"; sed -e 's/^/    /' "$tmp_resp" 1>&2
    rm -f "$tmp_resp"
    return 1
  fi
}

bootstrap_default_roles() {
  local registered_key="${ROLE_TENANT_PREFIX}|registered"
  local superadmin_key="${ROLE_TENANT_PREFIX}|superadmin"

  log "Bootstrapping default roles..."
  if role_exists "$registered_key"; then
    log "Role exists: ${registered_key}"
  else
    create_role "registered" "$registered_key" || return 1
  fi

  if role_exists "$superadmin_key"; then
    log "Role exists: ${superadmin_key}"
  else
    create_role "superadmin" "$superadmin_key" || return 1
  fi
}

main() {
  require_bin curl

  log "DGRAPH_URL=${DGRAPH_URL}"
  log "ALTER_ENDPOINT=${ALTER_ENDPOINT}"
  log "SCHEMA_DIR=${SCHEMA_DIR}"
  log "DRY_RUN=${DRY_RUN}"

  for mod in "${MODULES[@]}"; do
    local dir="${SCHEMA_DIR}/${mod}"
    if [[ ! -d "$dir" ]]; then
      log "Skipping missing module directory: ${dir}"
      continue
    fi
    shopt -s nullglob
    local files=("$dir"/*.dql)
    shopt -u nullglob
    if (( ${#files[@]} == 0 )); then
      log "No .dql files in ${dir}, skipping."
      continue
    fi
    for f in "${files[@]}"; do
      apply_file "$f"
    done
  done

  # Ensure default roles exist after schema is applied
  bootstrap_default_roles

  log "All schema modules applied successfully."
}

main "$@"
