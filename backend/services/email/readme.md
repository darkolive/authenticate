# Email Service

This package centralizes email sending and provider integrations for the DO Study platform.

## Architecture

- The `agents/communication/HermesMailer` agent orchestrates system email sending and delegates here.
- This package implements provider-specific integrations (e.g., MailerSend) behind the `EmailProvider` interface.
- Switching providers only touches this package; agent callers remain unchanged.

## Files

- `email.go` – Service facade and provider routing.
- `mailersend.go` – MailerSend provider implementation (uses Modus HTTP connection).
- `queue.go` – Async queue (currently disabled under WASM).

## Usage

Preferred (from agents):
```go
import "backend/services/email"

// Send OTP email
resp, err := email.SendOTPEmail("user@example.com", "123456")

// Send custom email
resp, err := email.SendEmail(email.EmailRequest{
    To:         "user@example.com",
    From:       email.DefaultFromEmail,
    Subject:    "Your Subject",
    TemplateID: "template-id",
    Variables:  map[string]string{"variable_name": "value"},
})
```

HermesMailer agent delegation:
```go
import hermes "backend/agents/communication/HermesMailer"

m := hermes.NewHermesMailer("")
_, _ = m.Send(ctx, &hermes.SendTemplateRequest{ /* ... */ })
```

## Configuration

- Provider connection (API base URL and headers) is defined in `backend/modus.json` under `connections.mailersend`.
- Secrets for local dev (e.g., `MODUS_MAILERSEND_API_KEY`) go in `backend/.env.dev.local`.
- Template IDs are configured in `mailersend.go` (`OTPTemplateID`, `WelcomeTemplateID`).

## Benefits

1. **Separation of Concerns**: Agents focus on messaging intent; providers live here.
2. **Swap Providers**: Implement `EmailProvider` and call `SetPrimaryProvider()` to switch.
3. **Consistency**: Single place for templates, defaults, and HTTP integration.
4. **Testability**: `EmailProvider` can be mocked in unit tests.
