# 🛡️ Aegis — The Guardian of Secrets

_Aegis_ is the **encryption and masking agent** for the Modus API ecosystem. Inspired by the mythological shield of Athena and Zeus, **Aegis defends critical data**, masks sensitive identity, and ensures only those bearing the right keys may pass.

---

## 🔐 Key Features

- AES-256-GCM encryption at rest (derived from `AEGIS_MASTER_KEY`)
- Deterministic HMAC-SHA256 blind indexes for equality search/dedup
- Simple Go service with `Encrypt`, `Decrypt`, and `HMAC` helpers
- Optional role-based gates using `aegis.Allowed(userRoles, ...roles)`
- No external Vault required; ideal for dev/debugging

---

## 🧰 Usage (Go → Agents/Services)

```go
import (
  aegis "backend/services/aegis"
)

// 1) Encrypt at rest (store only ciphertext)
ct, err := aegis.Encrypt("pii-identity", []byte("Ada"))
// -> store as firstName_enc: ct

// 2) Blind index for equality lookup/dedup (deterministic, not reversible)
bi, err := aegis.HMAC("pii-identity-hmac", []byte(strings.ToLower("Ada")))
// -> store as firstName_bi: bi

// 3) Decrypt when allowed on server-side
pt, err := aegis.Decrypt("pii-identity", ct)
// -> "Ada"

// 4) Simple role gate (example)
if !aegis.Allowed([]string{"registered"}, "admin", "superadmin") {
  // deny privileged action
}
```

### Dgraph storage pattern

- Store encrypted values in `*_enc` predicates, e.g. `firstName_enc`, `value_enc`.
- Store blind indexes in `*_bi` predicates, e.g. `firstName_bi`, `value_bi`.
- Query by blind index for equality filtering; decrypt `*_enc` only for the data subject or privileged roles.

Example N-Quads snippet (conceptual):

```
<userUID> <firstName_enc> "aegis:v1:..." .
<userUID> <firstName_bi>  "hexhmac..." .
```

---

## 🧭 Namespaces and policies

- `pii-contact` for emails/phones (channels)
- `pii-contact-hmac` for channel blind indexes
- `pii-identity` for personal names/displayName
- `pii-identity-hmac` for identity blind indexes

Naming the namespace lets Aegis derive separate subkeys per domain of data.

Role-based access: enforce decryption on server-side only; e.g. gate decrypts to the data subject and/or admins. Use `aegis.Allowed(...)` and your existing authz checks.

---

## ⚙️ Environment

- `AEGIS_MASTER_KEY` — secret for key derivation.
  - Dev default exists but is insecure. For production, set a strong value via your secret manager.

No Vault connection is required. This simplifies local debugging and reduces moving parts.

---

## 🔄 Migrating from Vault/tokenization

- Replace `backend/services/vault` usages with `backend/services/aegis`:
  - `Encrypt(key, data)` → `aegis.Encrypt(namespace, data)`
  - `Decrypt(key, ciphertext)` → `aegis.Decrypt(namespace, ciphertext)`
  - `HMAC(key, input)` → `aegis.HMAC(namespace, input)`
- Keep the same schema predicates (`*_enc`, `*_bi`).
- Remove tokenization where present; prefer encryption-at-rest + blind index for equality lookups.

---

## ✅ Current integrations

- `backend/agents/profile/Persona/*` uses Aegis for persona fields.
- `backend/agents/auth/Proteus/*` uses Aegis for channel values.
- `backend/agents/auth/HecateRegister/*` creates encrypted channel records and no longer tokenizes PII.
