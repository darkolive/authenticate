# ChronosSession

**Origin:** Greek Mythology  
**Inspired by:** Chronos, the embodiment of Time—creator of moments and inevitability of endings.

## Purpose

Manages the **lifecycle** of every user session: issuance, validation, renewal, and expiration.

## Core Responsibilities

1. **Issue Tokens**
   - Create signed session tokens with `issuedAt` & `expiresAt` claims.
2. **Validate Access**
   - On each request, compare current time to `expiresAt`; deny if expired.
3. **Refresh Sessions**
   - Extend a valid session’s `expiresAt` (configurable sliding window).
4. **Revoke Sessions**
   - Immediately expire tokens on logout, credential change, or admin action.
5. **Emit Audit Events**
   - Log issuance, refresh, expiry, and revocation through `ThemisLog`.

## Configuration

- **TTL** (`SESSION_TTL`) in your `.env`
- **Refresh window** (`SESSION_REFRESH_WINDOW`)

---

_By invoking ChronosSession, you entrust your session lifecycles to the very force that governs all things temporal._
