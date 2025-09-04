package CerberusMFA

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "strings"
    "time"

    "backend/agents/audit"
    "github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// CerberusMFARequest is the input to the Cerberus gateway after OTP verification
// Note: recipient is required so we can compute channelHash for UserChannels lookup
// channelDID is optional; if not provided we compute it from channelType:recipient
//
// channelType must be one of: "email", "phone"
//
// Frontend source of truth: recipient and channelType captured during OTP flow
// and carried forward after OTP verification.
//
// Security: IPAddress and UserAgent are used only for audit metadata and
// privacy-preserving hashing in the audit agent.
//
type CerberusMFARequest struct {
    ChannelDID  string `json:"channelDID,omitempty"`
    ChannelType string `json:"channelType"`
    Recipient   string `json:"recipient"`

    IPAddress   string `json:"ipAddress,omitempty"`
    UserAgent   string `json:"userAgent,omitempty"`
}

// CerberusMFAResponse communicates the route and available auth methods
// UserID here refers to the public DID of the user (not the Dgraph UID)
// availableMethods: e.g. ["webauthn", "passwordless"]
//
type CerberusMFAResponse struct {
    UserExists        bool     `json:"userExists"`
    Action            string   `json:"action"` // "signin" or "register"
    UserID            string   `json:"userId,omitempty"`
    AvailableMethods  []string `json:"availableMethods"`
    NextStep          string   `json:"nextStep"`
    Message           string   `json:"message,omitempty"`
    AuditEventID      string   `json:"auditEventId,omitempty"`
}

// hashString computes a hex-encoded SHA-256 of the input
func hashString(s string) string {
    sum := sha256.Sum256([]byte(s))
    return hex.EncodeToString(sum[:])
}

// normalizeRecipient mirrors frontend normalization to ensure consistent hashing
func normalizeRecipient(channelType, recipient string) string {
    if recipient == "" {
        return ""
    }
    if strings.ToLower(channelType) == "email" {
        return strings.ToLower(strings.TrimSpace(recipient))
    }
    return strings.TrimSpace(recipient)
}

// generateChannelDID mirrors CharonOTP's DID generation: hash("<channel>:<recipient>")
func generateChannelDID(channel, recipient string) string {
    return hashString(fmt.Sprintf("%s:%s", channel, recipient))
}

// evaluateAvailableMethods checks what MFA methods can be offered for a given user UID
// Currently supports WebAuthn detection and passwordless fallback.
func evaluateAvailableMethods(userUID string) (methods []string, err error) {
    // New users: passwordless path to complete registration
    if userUID == "" {
        return []string{"passwordless"}, nil
    }

    // Existing users: prefer WebAuthn if any credential exists
    q := fmt.Sprintf(`{
        u(func: uid(%s)) {
            creds: ~user @filter(type(WebAuthnCredential)) { uid }
        }
    }`, userUID)

    res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if qerr != nil {
        return []string{"passwordless"}, fmt.Errorf("webauthn lookup failed: %v", qerr)
    }
    if res.Json == "" {
        return []string{"passwordless"}, nil
    }
    var parsed struct {
        U []struct {
            Creds []struct{ UID string `json:"uid"` } `json:"creds"`
        } `json:"u"`
    }
    if err := json.Unmarshal([]byte(res.Json), &parsed); err != nil {
        return []string{"passwordless"}, fmt.Errorf("webauthn lookup parse failed: %v", err)
    }
    if len(parsed.U) > 0 && len(parsed.U[0].Creds) > 0 {
        return []string{"webauthn"}, nil
    }
    // Temporary fallback when user has no passkey yet
    return []string{"passwordless"}, nil
}

// updateChannelUsage sets lastUsedAt to now and optionally verified=true for the channel UID
func updateChannelUsage(channelUID string, setVerified bool) error {
    if channelUID == "" {
        return nil
    }
    now := time.Now().UTC().Format(time.RFC3339)
    nquads := fmt.Sprintf(`<%s> <lastUsedAt> %q^^<http://www.w3.org/2001/XMLSchema#dateTime> .`, channelUID, now)
    if setVerified {
        nquads += fmt.Sprintf("\n<%s> <verified> \"true\"^^<http://www.w3.org/2001/XMLSchema#boolean> .", channelUID)
    }
    mut := dgraph.NewMutation().WithSetNquads(nquads)
    if _, err := dgraph.ExecuteMutations("dgraph", mut); err != nil {
        return fmt.Errorf("failed to update channel usage: %v", err)
    }
    return nil
}

// Evaluate performs the CerberusMFA decision based on UserChannels
func Evaluate(req CerberusMFARequest) (CerberusMFAResponse, error) {
    // Validate inputs
    if req.ChannelType == "" {
        return CerberusMFAResponse{Action: "register"}, fmt.Errorf("channelType is required")
    }
    if req.Recipient == "" {
        return CerberusMFAResponse{Action: "register"}, fmt.Errorf("recipient is required")
    }
    if req.ChannelType != "email" && req.ChannelType != "phone" {
        return CerberusMFAResponse{Action: "register"}, fmt.Errorf("unsupported channelType: %s", req.ChannelType)
    }

    // Compute hashes (support both raw and normalized recipients for backward compatibility)
    rawRecipient := req.Recipient
    rawHash := hashString(rawRecipient)
    normRecipient := normalizeRecipient(req.ChannelType, rawRecipient)
    hashFilter := fmt.Sprintf("eq(channelHash, %q)", rawHash)
    if normRecipient != rawRecipient {
        normHash := hashString(normRecipient)
        // Match either the raw or normalized hash
        hashFilter = fmt.Sprintf("(eq(channelHash, %q) or eq(channelHash, %q))", rawHash, normHash)
    }
    computedDID := generateChannelDID(req.ChannelType, normRecipient)
    if req.ChannelDID == "" {
        req.ChannelDID = computedDID
    }

    // Timezone/local time enrichment (fallback to UTC). When Modus Local Time SDK for Go is available,
    // replace this block with SDK-driven normalization based on client-provided context.
    utcNow := time.Now().UTC()
    tzName := "UTC"
    localNow := utcNow
    offsetMinutes := 0

    // Lookup UserChannels by (channelType, channelHash) and follow user edge
    q := fmt.Sprintf(`{
        ch(func: eq(channelType, %q)) @filter(%s) {
            uid
            verified
            userId
            user { uid did status }
        }
    }`, req.ChannelType, hashFilter)

    result, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil {
        return CerberusMFAResponse{Action: "register"}, fmt.Errorf("failed to query UserChannels: %v", err)
    }

    var parsed struct {
        Ch []struct {
            UID      string          `json:"uid"`
            Verified bool            `json:"verified"`
            UserID   string          `json:"userId"`
            User     json.RawMessage `json:"user"`
        } `json:"ch"`
    }
    if result.Json != "" {
        if perr := json.Unmarshal([]byte(result.Json), &parsed); perr != nil {
            return CerberusMFAResponse{Action: "register"}, fmt.Errorf("failed to parse UserChannels response: %v", perr)
        }
    }

    // Default new-user path
    if len(parsed.Ch) == 0 || len(parsed.Ch[0].User) == 0 {
        // Audit: route to registration
        auditID, _ := audit.Log(audit.EntryParams{
            Category:    "AUTHENTICATION",
            Action:      "MFA_ROUTED",
            ObjectType:  "UserChannels",
            ObjectID:    req.ChannelDID,
            PerformedBy: "CerberusMFA",
            Source:      "CerberusMFA",
            Severity:    "INFO",
            Details: map[string]interface{}{
                "userExists":            false,
                "channelType":           req.ChannelType,
                "channelDID":            req.ChannelDID,
                "nextStep":              "register",
                "timezone":              tzName,
                "localTime":             localNow.Format(time.RFC3339),
                "timestampUTC":          utcNow.Format(time.RFC3339),
                "timezoneOffsetMinutes": offsetMinutes,
            },
            IPAddress:    req.IPAddress,
            UserAgentRaw: req.UserAgent,
            Timestamp:    utcNow,
        })

        return CerberusMFAResponse{
            UserExists:       false,
            Action:           "register",
            UserID:           "",
            AvailableMethods: []string{"passwordless"},
            NextStep:         "Complete user registration",
            Message:          "Welcome! Let's create your account.",
            AuditEventID:     auditID,
        }, nil
    }

    // Parse user object (can be object or array)
    var user struct {
        UID    string `json:"uid"`
        DID    string `json:"did"`
        Status string `json:"status"`
    }
    raw := parsed.Ch[0].User
    switch raw[0] {
    case '{':
        if uerr := json.Unmarshal(raw, &user); uerr != nil {
            return CerberusMFAResponse{Action: "register"}, fmt.Errorf("failed to parse user object: %v", uerr)
        }
    case '[':
        var arr []struct {
            UID    string `json:"uid"`
            DID    string `json:"did"`
            Status string `json:"status"`
        }
        if uerr := json.Unmarshal(raw, &arr); uerr != nil || len(arr) == 0 {
            return CerberusMFAResponse{Action: "register"}, fmt.Errorf("failed to parse user array")
        }
        user = arr[0]
    default:
        return CerberusMFAResponse{Action: "register"}, fmt.Errorf("unexpected user JSON format")
    }

    // Evaluate available methods (webauthn + passwordless)
    methods, merr := evaluateAvailableMethods(user.UID)
    if merr != nil {
        // Non-fatal; proceed with passwordless only
        methods = []string{"passwordless"}
    }

    // Update channel usage; if channel wasn't verified, set it true now (post-OTP verified)
    _ = updateChannelUsage(parsed.Ch[0].UID, !parsed.Ch[0].Verified)

    // Audit success path
    auditID, _ := audit.Log(audit.EntryParams{
        Category:    "AUTHENTICATION",
        Action:      "MFA_ROUTED",
        ObjectType:  "User",
        ObjectID:    user.DID,
        PerformedBy: "CerberusMFA",
        Source:      "CerberusMFA",
        Severity:    "INFO",
        Details: map[string]interface{}{
            "userExists":            true,
            "channelType":           req.ChannelType,
            "channelDID":            req.ChannelDID,
            "availableMethods":      methods,
            "nextStep":              "signin",
            "timezone":              tzName,
            "localTime":             localNow.Format(time.RFC3339),
            "timestampUTC":          utcNow.Format(time.RFC3339),
            "timezoneOffsetMinutes": offsetMinutes,
        },
        IPAddress:    req.IPAddress,
        UserAgentRaw: req.UserAgent,
        Timestamp:    utcNow,
    })

    return CerberusMFAResponse{
        UserExists:       true,
        Action:           "signin",
        UserID:           user.DID,
        AvailableMethods: methods,
        NextStep:         "Choose authentication method",
        Message:          "Welcome back! Please complete authentication.",
        AuditEventID:     auditID,
    }, nil
}
