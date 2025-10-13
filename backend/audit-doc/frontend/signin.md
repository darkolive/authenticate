# Frontend Sign-in — Audit & Flow Documentation

This document explains how the Next.js frontend handles the sign-in and registration flows, including OTP and passkeys (WebAuthn). It maps user actions to API routes and server actions, and shows how those in turn call backend GraphQL resolvers.

## Overview

- **Primary UI**: `frontend/src/app/signin/page.tsx`
- **API routes used**:
  - `frontend/src/app/api/auth/send-otp/route.ts`
  - `frontend/src/app/api/auth/verify-otp/route.ts`
  - `frontend/src/app/api/auth/cerberus-gate/route.ts`
  - `frontend/src/app/api/auth/register/route.ts`
  - Passkeys (janusface):
    - `frontend/src/app/api/auth/webauthn/register/begin/route.ts`
    - `frontend/src/app/api/auth/webauthn/register/finish/route.ts`
    - `frontend/src/app/api/auth/webauthn/login/begin/route.ts`
    - `frontend/src/app/api/auth/webauthn/login/finish/route.ts`
- **Server actions (GraphQL)**: `frontend/src/lib/actions.ts`
- **Helpers**: `frontend/src/lib/utils.ts`

## GraphQL backend mapping (via actions)

- `sendOTP()` -> GraphQL `sendOTP` -> backend `SendOTP()` -> `CharonOTP.SendOTP()`
- `verifyOTP()` -> GraphQL `verifyOTP` -> backend `VerifyOTP()` -> `CharonOTP.VerifyOTP()`
- `cerberusGate()` -> GraphQL `cerberusGate` -> backend `CerberusGate()` -> `CerberusMFA.Evaluate()`
- `registerUser()` -> GraphQL `registerUser` -> backend `RegisterUser()` -> `HecateRegister.RegisterUser()`
- `beginjanusfaceRegistration()` / `finishjanusfaceRegistration()` -> GraphQL -> backend `JanusFace.BeginRegistration/FinishRegistration()`
- `beginjanusfaceLogin()` / `finishjanusfaceLogin()` -> GraphQL -> backend `JanusFace.BeginLogin/FinishLogin()`

All GraphQL calls are performed by `frontend/src/lib/actions.ts` using `BACKEND_GRAPHQL_URL` and optional `MODUS_API_KEY` (attached as Bearer when it looks like a JWT).

---

## UI flow in `signin/page.tsx`

### Send OTP

- **Who**: User submits channel + recipient on `signin/page.tsx`.
- **Where**: `onSendOTP()` posts to `/api/auth/send-otp`.
- **How**: API route `api/auth/send-otp/route.ts`:
  - Validates input, defaults `channel` to `email`.
  - Normalizes `recipient` (`normalizeRecipient()` in `utils.ts`).
  - Extracts `ipAddress` (`getClientIp()`), `userAgent`.
  - Calls `sendOTP()` server action (GraphQL to backend `SendOTP()` -> `CharonOTP.SendOTP()` -> Twilio/email).
- **Why**: Start OTP verification, generating OTP and dispatching via Email/SMS/WhatsApp.

### Verify OTP and establish auth context

- **Who**: User enters OTP code on `signin/page.tsx`.
- **Where**: `onVerifyOTP()` posts to `/api/auth/verify-otp`.
- **How**: API route `api/auth/verify-otp/route.ts`:
  - Validates inputs, computes `channelType` (`email` or `phone`) for normalization.
  - Normalizes `recipient`.
  - Calls `verifyOTP()` server action (GraphQL to backend `VerifyOTP()` -> `CharonOTP.VerifyOTP()`).
  - On success, sets HttpOnly cookies:
    - `channelDID` (unique DID for channel)
    - `authRecipient` (normalized recipient)
    - `authChannelType` (`email` or `phone`)
- **Why**: Mark OTP as verified and persist minimal auth context for subsequent steps.

### Cerberus decisioning: sign in vs register

- **Who**: `signin/page.tsx` calls Cerberus after OTP verification.
- **Where**: POST to `/api/auth/cerberus-gate`.
- **How**: API route `api/auth/cerberus-gate/route.ts`:
  - Normalizes recipient; computes or uses provided `channelDID`.
  - Adds audit hints (`ipAddress`, `userAgent`).
  - Calls `cerberusGate()` (GraphQL -> backend `CerberusGate()` -> `CerberusMFA.Evaluate()`).
  - Returns `action` (`signin` or `register`), `userId` if known, optional merge hints.
- **Why**: Decide whether to authenticate an existing user or complete registration, and advertise next steps.

### Passkey (janusface) login

- **Who**: User chooses passkey sign-in.
- **Where**:
  - Begin: `/api/auth/webauthn/login/begin`
  - Finish: `/api/auth/webauthn/login/finish`
- **How**:
  - Begin route resolves `userId` with Cerberus using `channelDID`/cookies, calls `beginjanusfaceLogin()` to obtain PublicKeyCredentialRequestOptions (`optionsJSON`, `challenge`).
  - Client calls `navigator.credentials.get()` and posts the credential to Finish route.
  - Finish route calls `finishjanusfaceLogin()`; on success, sets session cookies `__Host-hm_session` (secure) and `hm_session` (dev-only), then returns.
- **Why**: Authenticate via WebAuthn and establish a session for protected pages.

### Passkey (janusface) registration

- **Who**: User adds a passkey (recommended after OTP/registration).
- **Where**:
  - Begin: `/api/auth/webauthn/register/begin`
  - Finish: `/api/auth/webauthn/register/finish`
- **How**:
  - Begin route resolves/creates `userId`:
    - Uses cookies + Cerberus.
    - If Cerberus indicates `register`, it calls `registerUser()` to create the user on-the-fly so passkey registration can proceed.
  - Calls `beginjanusfaceRegistration()` to get PublicKeyCredentialCreationOptions.
  - Client calls `navigator.credentials.create()` and posts to Finish route.
  - Finish route calls `finishjanusfaceRegistration()`; on success, sets session cookies `__Host-hm_session` and dev `hm_session`.
- **Why**: Bind a passkey to the account and (optionally) sign the user in immediately.

### Profile-based onboarding (post-auth)

- After a session is established, onboarding is handled on `/onboarding` (see `frontend/src/app/onboarding/page.tsx`) posting to `/api/profile/complete`, which calls `updateUserpersona()` and clears any legacy gating cookie.

---

## API routes — Who/Where/How/Why

- **`/api/auth/send-otp`**
  - **Where**: `frontend/src/app/api/auth/send-otp/route.ts`
  - **How**: Normalizes input, collects IP/UA, calls `sendOTP()`.
  - **Why**: Initiate MFA/OTP delivery via backend.

- **`/api/auth/verify-otp`**
  - **Where**: `frontend/src/app/api/auth/verify-otp/route.ts`
  - **How**: Calls `verifyOTP()`, sets `channelDID`, `authRecipient`, `authChannelType` cookies on success.
  - **Why**: Complete OTP verification and persist context for next steps.

- **`/api/auth/cerberus-gate`**
  - **Where**: `frontend/src/app/api/auth/cerberus-gate/route.ts`
  - **How**: Normalizes recipient, computes/uses `channelDID`, forwards IP/UA to `cerberusGate()`.
  - **Why**: Decide signin vs register and gather method hints, possibly merge hints.

- **`/api/auth/register`**
  - **Where**: `frontend/src/app/api/auth/register/route.ts`
  - **How**: Ensures non-null `displayName`, resolves timezone/language, normalizes recipient, calls `registerUser()`.
  - **Why**: Complete profile bootstrap when Cerberus indicates registration.

- **Passkeys `/api/auth/webauthn/*`**
  - **Where**: `frontend/src/app/api/auth/webauthn/**`
  - **How**: Resolve `userId` via Cerberus and cookies; begin returns WebAuthn options; finish persists credential or verifies assertion and sets session cookies.
  - **Why**: Provide passwordless UX using WebAuthn.

---

## Cookies & Security

- **Auth context cookies** (set by verify-otp):
  - `channelDID` (HttpOnly, short-lived)
  - `authRecipient` (HttpOnly)
  - `authChannelType` (HttpOnly)
- **Session cookies** (set by janusface finish routes):
  - `__Host-hm_session` (Secure, HttpOnly, Path=/)
  - `hm_session` (dev-only fallback for local HTTP)
- **Normalization**: `normalizeRecipient()` ensures consistent hashing downstream; emails lowercased.
- **Server-only GraphQL**: `actions.ts` runs on server only and uses `BACKEND_GRAPHQL_URL` and optional `MODUS_API_KEY`.

## Related files

- `frontend/src/app/signin/page.tsx`
- `frontend/src/lib/actions.ts`
- `frontend/src/lib/utils.ts`
- `frontend/src/app/api/auth/send-otp/route.ts`
- `frontend/src/app/api/auth/verify-otp/route.ts`
- `frontend/src/app/api/auth/cerberus-gate/route.ts`
- `frontend/src/app/api/auth/register/route.ts`
- `frontend/src/app/api/auth/webauthn/register/begin/route.ts`
- `frontend/src/app/api/auth/webauthn/register/finish/route.ts`
- `frontend/src/app/api/auth/webauthn/login/begin/route.ts`
- `frontend/src/app/api/auth/webauthn/login/finish/route.ts`
- Backend reference: `backend/main.go`, `backend/agents/auth/CharonOTP/CharonOTP.go`, `backend/agents/auth/JanusFace/JanusFace.go`, `backend/agents/auth/CerberusMFA/`

