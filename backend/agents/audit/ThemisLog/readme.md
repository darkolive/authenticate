# ThemisLog

**Origin:** Greek Mythology  
**Inspired by:** Themis, Titaness of divine law, order, and impartial justice.

## Purpose

ThemisLog is our **ISO-aligned audit-trail agent**, ensuring that every authentication, authorization, and PII-access event is:

- **Fairly weighed**: Conforms to the schema and policy rules.
- **Impartially recorded**: Immutable, append-only storage.
- **Easily queried**: Supports compliance reporting with filterable logs.
- **Securely retained**: Honors retention and archival policies.

## Core Responsibilities

1. **Capture Events**
   - Subscribes to internal Modus streams (`AuthEvents`, `AgentDecisions`, `PIIAccess`).
2. **Validate & Serialize**
   - Maps raw events into `AuditEvent` schema (timestamp, actor, action, context).
3. **Store Append-Only**
   - Writes events to `.modusdb` or an external WORM store with integrity hashes.
4. **Expose Interface**
   - Provides gRPC/HTTP endpoints for `GET /audit?actor=X&from=…&to=…`
   - Integrates with your compliance dashboard.
5. **Retention Management**
   - Applies ISO 27001 retention schedules (e.g., 2 years for auth logs, 7 years for PII access).

## Getting Started

1. **Configuration**
   - Define your retention policy in `internal/audit/policy.yaml`.
2. **Deploy**
   - Ensure `.env` contains `AUDIT_STORE_URI` and `AUDIT_KEY`.
   - Register `ThemisLog` stream in `modus.json`.
3. **Verify**
   - Trigger a login and confirm the event appears via `GET /audit`.

---

_By entrusting your audit trail to ThemisLog, you invoke the impartial wisdom of the ancient Titaness to guard your system’s integrity._
