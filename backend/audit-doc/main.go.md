# backend/main.go — Audit & Flow Documentation

This document explains what each exported function in `backend/main.go` does, including who calls it, where it delegates work, how it behaves, and why it exists. It also links to relevant agents and services.

## Overview

- **Purpose**: `backend/main.go` exposes API entrypoints that are bound by Modus to exported functions. Each function is a thin wrapper that validates input and delegates to a specific agent/service.
- **Invocation**: The Modus-generated glue in `backend/modus_pre_generated.go` maps exported names to these functions (e.g., `sendOTP` -> `SendOTP`). Requests typically come from GraphQL/resolver bindings.
- **Pattern**: Most wrappers handle `nil` requests defensively, construct a zero-value request, call the agent, and transform errors into response objects with `Message`.

## How Modus Glue Calls These

See `backend/modus_pre_generated.go` for the bindings:

```go
//go:export sendOTP                 -> SendOTP(req *CharonOTP.OTPRequest)
//go:export getLinkedChannels       -> GetLinkedChannels(req *Proteus.GetLinkedChannelsRequest)
//go:export linkChannelStart        -> LinkChannelStart(req *Proteus.LinkChannelStartRequest)
//go:export linkChannelConfirm      -> LinkChannelConfirm(req *Proteus.LinkChannelConfirmRequest)
//go:export updateUserpersona       -> UpdateUserpersona(req *Persona.UpdatepersonaRequest)
//go:export ispersonaComplete       -> IspersonaComplete(req *Persona.CompletepersonaRequest)
//go:export getUserPII              -> GetUserPII(req *Persona.GetPIIRequest)
//go:export verifyOTP               -> VerifyOTP(req *CharonOTP.VerifyOTPRequest)
//go:export registerUser            -> RegisterUser(req *HecateRegister.UserRegistrationRequest)
//go:export cerberusGate            -> CerberusGate(req *CerberusMFA.CerberusMFARequest)
//go:export validateSession         -> ValidateSession(req *ChronosSession.ValidationRequest)
//go:export beginjanusfaceRegistration -> BeginjanusfaceRegistration(req *JanusFace.BeginRegistrationRequest)
//go:export finishjanusfaceRegistration -> FinishjanusfaceRegistration(req *JanusFace.FinishRegistrationRequest)
//go:export beginjanusfaceLogin     -> BeginjanusfaceLogin(req *JanusFace.BeginLoginRequest)
//go:export finishjanusfaceLogin    -> FinishjanusfaceLogin(req *JanusFace.FinishLoginRequest)
```

These names are what external callers (GraphQL resolvers) invoke. The wrappers here then call into the agents.

## Dependencies and Agents

- **OTP & MFA**: `backend/agents/auth/CharonOTP/CharonOTP.go`
- **Channel Linking**: `backend/agents/auth/Proteus/Proteus.go`
- **Profile (persona)**: `backend/agents/profile/Persona/Persona.go`, `Persona/Decrypt.go`
- **Passkeys (janusface)**: `backend/agents/auth/JanusFace/JanusFace.go`
- **Sessions**: `backend/agents/sessions/ChronosSession/*.go`
- **Twilio (OTP SMS/WhatsApp)**: `backend/services/twilio/twilio.go`
- **Dgraph access**: via Modus SDK inside agents
- **Vault transit & HMAC**: in Persona and Proteus agents

---

## SendOTP

- **Who calls**: `sendOTP` (Modus export) from GraphQL.
- **Where it goes**: Delegates to `CharonOTP.SendOTP(context.Background(), req)`.
- **How it works**:
  - Accepts `*charonotp.OTPRequest{Channel, Recipient}`.
  - Guards `nil` by creating an empty request.
  - Returns `charonotp.OTPResponse` with `Sent`, `ExpiresAt`, and error `Message` when applicable.
- **Why**: Central entry to trigger OTP via Email/SMS/WhatsApp. Downstream agent handles generation, Dgraph storage, Twilio/email dispatch, and audit logs.
- **Side effects** (in agent):
  - Stores OTP record in Dgraph (`ChannelOTP`).
  - Sends via Twilio or queues email.
  - Emits audit events (`OTP_SEND_ATTEMPT`, `OTP_SENT`, `OTP_GENERATED`, etc.).
- **Security**: No plaintext OTP persisted; only hashes. Recipient normalized for stable hashing.

## GetLinkedChannels

- **Who calls**: `getLinkedChannels` from GraphQL.
- **Where**: `Proteus.GetLinkedChannels(context.Background(), req)`.
- **How**:
  - Inputs `UserID` (the DID).
  - Resolves user’s `IdentityCluster` and returns `channels` with decrypted displayable values.
- **Why**: Show which communication channels are linked to the user’s identity cluster.
- **Side effects**: Read-only; decrypts channel values for display via Vault.
- **Security**: Uses encrypted fields and decrypts server-side for subject display contexts.

## LinkChannelStart

- **Who**: `linkChannelStart`.
- **Where**: `Proteus.LinkChannelStart(ctx, req)`.
- **How**:
  - Validates `UserID`, `ChannelType` (email/sms/whatsapp), `Value`.
  - Calls `CharonOTP.SendOTP(...)` within Proteus to issue challenge.
  - Returns masked destination, `linkId` (OTP id), and expiry.
- **Why**: Begin linking flow with OTP challenge.
- **Side effects**: OTP issuance stored in Dgraph; transport via Twilio/email.
- **Security**: Masks destination; no plaintext stored in UserChannels/Channel records.

## LinkChannelConfirm

- **Who**: `linkChannelConfirm`.
- **Where**: `Proteus.LinkChannelConfirm(ctx, req)`.
- **How**:
  - For email/sms/whatsapp: verifies OTP via `CharonOTP.VerifyOTP`.
  - Ensures an `IdentityCluster` for the user; creates/loads `Channel` (encrypted at-rest).
  - Ownership resolution: if the channel is owned by another cluster, reassigns to the caller’s cluster (audits `CHANNEL_UNLINKED` and `CHANNEL_LINKED`).
  - Mirrors to legacy `UserChannels` for Cerberus lookups.
- **Why**: Attach verified channels to identity; support claim/transfer when validly proven via OTP.
- **Side effects**: Writes to Dgraph (Channel, ownership edges, verification timestamps, legacy mirror) and audit logs.
- **Security**: Encryption for channel values; blind indexes and hashes for lookup.

## UpdateUserpersona

- **Who**: `updateUserpersona`.
- **Where**: `Persona.UpdateUserpersona(ctx, req)`.
- **How**:
  - Locates user by DID; encrypts provided fields (`firstName`, `lastName`, `displayName`) and writes ciphertext plus blind indexes.
  - Emits `persona_UPDATED` audit with before/after completeness flags and metadata like IP/User-Agent.
- **Why**: Persist profile PII securely and enable onboarding gating.
- **Side effects**: Dgraph writes of encrypted fields and indices; audit log emission.
- **Security**: No plaintext persisted; Vault transit encryption + HMAC blind index.

## IspersonaComplete

- **Who**: `ispersonaComplete`.
- **Where**: `Persona.IspersonaComplete(req)`.
- **How**: Checks for presence of encrypted `displayName` or any of `firstName/lastName` to determine completeness.
- **Why**: Gate routes like `/dashboard` vs `/onboarding` server-side.
- **Side effects**: Read-only.

## GetUserPII

- **Who**: `getUserPII`.
- **Where**: `Persona.GetUserPII(ctx, req)`.
- **How**: Loads encrypted persona fields for the subject and decrypts via Vault transit. Returns plaintext plus ciphertext.
- **Why**: Support secure subject access and server-side rendering of profile fields.
- **Security**: Only intended for server-side subject reads; avoid rendering ciphertext to non-owners.

## VerifyOTP

- **Who**: `verifyOTP`.
- **Where**: `CharonOTP.VerifyOTP(req)`.
- **How**:
  - Matches `recipient` (raw/normalized) + `otpCode` hash in Dgraph, ensures not used/expired.
  - Marks OTP as verified/used, determines next action (`signin` or `register`) and `channelDID`.
- **Why**: Complete OTP challenge and route the caller.
- **Side effects**: Dgraph updates for OTP; audit logs for verification; may drive subsequent session issuance in higher layers.

## RegisterUser

- **Who**: `registerUser`.
- **Where**: `HecateRegister.RegisterUser(ctx, req)`.
- **How**: Completes user creation when required by flows like Cerberus post-OTP evaluation.
- **Why**: Support combined OTP + passwordless registration paths.
- **Side effects**: Writes new user and initial state.

## CerberusGate

- **Who**: `cerberusGate`.
- **Where**: `CerberusMFA.Evaluate(req)`.
- **How**: After OTP verification, evaluates whether the user exists and recommends `action` (`signin` vs `register`) and available methods.
- **Why**: Simple decisioning layer to orchestrate next steps.
- **Side effects**: Read-only.

## ValidateSession

- **Who**: `validateSession`.
- **Where**: `ChronosSession.Initialize()` then `ValidateSession(ctx, req)`.
- **How**:
  - Requires non-`nil` request and token.
  - Parses/validates JWT, checks Dgraph for revocation/validity, updates last-used timestamp.
  - Returns `Valid`, `UserID`, `ExpiresAt`, `Message`.
- **Why**: Server-side session gating for APIs and middleware.
- **Side effects**: Updates `lastUsed`; reads session record; can reflect revocation.
- **Security**: HMAC JWT with server secret; token hash stored (not token itself).

## BeginjanusfaceRegistration

- **Who**: `beginjanusfaceRegistration`.
- **Where**: `JanusFace.BeginRegistration(req)`.
- **How**:
- Validates user, creates a WebAuthn-like challenge, persists it, and returns `optionsJSON`, `challenge`, `expiresAt`. Emits audit `janusface_REG_BEGIN` with IP/User-Agent.
- **Why**: Start registration of passkey credentials.
- **Side effects**: Stores challenge; audit.

## FinishjanusfaceRegistration

- **Who**: `finishjanusfaceRegistration`.
- **Where**: `JanusFace.FinishRegistration(req)`.
- **How**:
  - Stores a credential skeleton for the user; idempotent if credential already present.
  - Attempts to issue a session (`ChronosSession.IssueSession`) upon success.
  - Audits `janusface_REG_FINISH`.
- **Why**: Complete passkey enrollment and log user in.
- **Side effects**: Writes credential node, issues session, writes session record, audits.

## BeginjanusfaceLogin

- **Who**: `beginjanusfaceLogin`.
- **Where**: `JanusFace.BeginLogin(req)`.
- **How**: Issues a login challenge (and optionally allowed credentials) and audits `janusface_LOGIN_BEGIN`.
- **Why**: Start passkey assertion flow.
- **Side effects**: Stores challenge; audit.

## FinishjanusfaceLogin

- **Who**: `finishjanusfaceLogin`.
- **Where**: `JanusFace.FinishLogin(req)`.
- **How**:
  - Verifies presence of credential for the user (skeleton verification; crypto verification TODO in agent).
  - Issues a session on success and audits `janusface_LOGIN_FINISH`.
- **Why**: Complete passkey login and establish a session.
- **Side effects**: Session issuance and storage; audit.

---

## Cross-Cutting Concerns

- **Error handling**: Wrappers always return a response object; on errors set `Message` and sensible defaults (`Success: false`, `Verified: false`, etc.).
- **Nil-guard**: For resilience, many wrappers construct default requests when `req == nil`.
- **Context**: Functions that call agents expecting context use `context.Background()`.
- **Audit**: Most auditing occurs within agents (`ThemisLog`), especially OTP, Proteus, and JanusFace flows.
- **Data protection**: PII and channel values are encrypted at-rest; queries use hashes and blind indexes.

## Related Files

- `backend/main.go`
- `backend/modus_pre_generated.go`
- `backend/agents/auth/CharonOTP/CharonOTP.go`
- `backend/agents/auth/Proteus/Proteus.go`
- `backend/agents/profile/Persona/Persona.go`, `Persona/Decrypt.go`
- `backend/agents/auth/JanusFace/JanusFace.go`
- `backend/agents/sessions/ChronosSession/*.go`
- `backend/services/twilio/twilio.go`

