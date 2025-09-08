# CerberusMFA Agent

## Mythology

**Cerberus (Greek Mythology)**
• Role: Three-headed dog guarding the gates of the underworld
• Why it's great: Multi-layered defense metaphor — perfect for multi-factor authentication
• Agent name: CerberusMFA, CerberusGate

## Purpose

CerberusMFA acts as the **authentication gateway** after OTP verification, determining whether users should proceed to sign-in or registration flows.

## Authentication Flow

```
1. 📧 CharonOTP: OTP verified → returns channelDID
2. 🐕 CerberusMFA: Check UserChannels by channelHash
3. 🔀 Decision:
   - Existing User → Sign-in (janusface + Passwordless fallback)
   - New User → Registration (janusface + Passwordless options + create Userpersona)
4. 📝 Audit Event: Record authentication attempt
5. ChronosSession: Create session for user
6. ChronosToken: Create token for user
7. ChronosCookie: Create cookie for user

```

## API

### Input

```json
{
  "channelDID": "hashed_email_or_phone",
  "channelType": "email" | "phone"
}
```

### Output - Existing User

```json
{
  "userExists": true,
  "action": "signin",
  "userId": "user_123",
  "availableMethods": ["janusface", "passwordless"],
  "nextStep": "Choose authentication method",
  "message": "Welcome back! Please complete authentication."
}
```

### Output - New User

```json
{
  "userExists": false,
  "action": "register",
  "userId": "",
  "availableMethods": ["passwordless"],
  "nextStep": "Complete user registration",
  "message": "Welcome! Let's create your account."
}
```

## Database Schema

### UserChannels Type

```dql
type UserChannels {
    userId: string @index(exact)           # Maps to internal User ID
    channelType: string @index(exact)      # email, phone, etc.
    channelHash: string @index(exact)      # Hashed channel identifier
    verified: bool @index(bool)            # Channel verification status
    primary: bool @index(bool)             # Primary channel for user
    createdAt: datetime @index(hour)       # When channel was added
    lastUsedAt: datetime @index(hour)      # Last authentication attempt
}
```

## Security Features

1. **Channel Verification**: Only verified channels allow sign-in
2. **Usage Tracking**: Updates `lastUsedAt` for security monitoring
3. **Primary Channel**: Supports multiple channels per user
4. **Audit Trail**: Full authentication attempt logging

## Integration

- **Input**: Receives channelDID from CharonOTP verification
- **Output**: Directs to janusface, Passwordless, or Registration agents
- **Database**: Uses UserChannels for user lookup and tracking

## Three-Headed Defense

1. **Head 1**: Channel verification (email/sms/whatsapp OTP)
2. **Head 2**: User existence validation (UserChannels lookup)
3. **Head 3**: Multi-factor completion (janusface/Passwordless)
