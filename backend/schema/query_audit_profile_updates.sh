#!/usr/bin/env bash
# Query recent PROFILE_UPDATED audit entries for a given userID (DID)
# Usage:
#   ./query_audit_profile_updates.sh <USER_ID> [LIMIT]
# Env:
#   DGRAPH_URL (default: http://localhost:8080)

set -euo pipefail

# Ensure required tools exist
require_bin() { command -v "$1" >/dev/null 2>&1 || { echo "Error: required binary '$1' not found in PATH" >&2; exit 1; }; }
require_bin curl
require_bin jq

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <USER_ID> [LIMIT]" 1>&2
  exit 1
fi

USER_ID="$1"
LIMIT="${2:-25}"
DGRAPH_URL="${DGRAPH_URL:-http://localhost:8080}"
QUERY_ENDPOINT="${DGRAPH_URL%/}/query"

read -r -d '' GQL <<'EOF'
{
  q(func: type(AuditEntry), orderdesc: timestamp, first: LIMIT_HERE) @filter(eq(category, "PROFILE") AND eq(action, "PROFILE_UPDATED") AND eq(objectId, "USER_ID_HERE")) {
    id
    category
    action
    objectType
    objectId
    performedBy
    timestamp
    details
    ipHash
    tenantId
    userAgent { uaKey raw }
  }
}
EOF

# Inject variables safely
escaped_user_id=$(printf '%s' "$USER_ID" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
GQL=${GQL/USER_ID_HERE/$escaped_user_id}
GQL=${GQL/LIMIT_HERE/$LIMIT}

PAYLOAD=$(jq -cn --arg q "$GQL" '{query: $q}')

curl -sS -X POST \
  -H 'Content-Type: application/json' \
  --data-binary "$PAYLOAD" \
  "$QUERY_ENDPOINT" | jq -C .
