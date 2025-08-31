# Authenticate

This repository contains the authentication backend and schema for the Hypermode platform.

## Structure

- `backend/` — Go backend, agents, and Dgraph schemas
  - Agents (auth, sessions, audit)
  - Schema (`backend/schema/`), with deploy script `deployschema.sh`

## Prerequisites

- Go 1.23+ (module sets `go 1.23.12`)
- Dgraph instance (configurable via `DGRAPH_URL`, defaults to `http://localhost:8080`)

## Build

```
cd backend
go build ./...
```

## Deploy Schema

Dry run:
```
cd backend
DRY_RUN=1 ./schema/deployschema.sh
```
Apply:
```
cd backend
./schema/deployschema.sh
```

Environment variables:
- `DGRAPH_URL` (e.g., `http://localhost:8080`)
- Optional: `CURL_OPTS`, `ALTER_ENDPOINT`, `ROLE_TENANT_PREFIX`

## Git

- Default branch: `main`
- Initial commit includes only the `backend/` directory

## Notes

- Audit logging follows a privacy-balanced approach (masked IP hashed to `ipHash`, normalized `UserAgent` linkage).
- See `backend/agents/` for agents like `HecateRegister`, `CharonOTP`, and `ChronosSession`.
