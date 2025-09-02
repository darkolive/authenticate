package HecateRegister

import (
	"context"
	"encoding/json"
	"fmt"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"time"

	"backend/agents/audit"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// UserRegistrationRequest represents the request to register a new user
type UserRegistrationRequest struct {
	// Channel information from CharonOTP verification
	ChannelDID   string `json:"channelDID"`   // Unique identifier from OTP verification
	ChannelType  string `json:"channelType"`  // "email" or "phone"
	Recipient    string `json:"recipient"`    // email address or phone number
	
	// User profile information
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	DisplayName  string `json:"displayName,omitempty"`
	
	// Optional profile data
	Timezone     string `json:"timezone,omitempty"`
	Language     string `json:"language,omitempty"`
	
	// Registration metadata
	IPAddress    string `json:"ipAddress,omitempty"`
	UserAgent    string `json:"userAgent,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// UserRegistrationResponse represents the response after user registration
type UserRegistrationResponse struct {
	Success      bool      `json:"success"`
	UserID       string    `json:"userId"`
	Message      string    `json:"message"`
	
	// PII tokenization results
	PIITokens    map[string]string `json:"piiTokens,omitempty"`
	
	// Identity verification status
	IdentityCheckID string `json:"identityCheckId,omitempty"`
	
	// Audit information
	AuditEventID    string    `json:"auditEventId,omitempty"`
	CreatedAt       time.Time `json:"createdAt"`
}

// PIITokenizationRequest for internal PII handling
type PIITokenizationRequest struct {
	FirstName   string `json:"firstName"`
	LastName    string `json:"lastName"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
}

// PIITokenizationResponse from internal/pii service
type PIITokenizationResponse struct {
	Tokens map[string]string `json:"tokens"`
	Status string           `json:"status"`
}

// AuditEvent for ISO compliance
type AuditEvent struct {
	EventType    string                 `json:"eventType"`
	UserID       string                 `json:"userId"`
	Timestamp    time.Time              `json:"timestamp"`
	IPAddress    string                 `json:"ipAddress,omitempty"`
	UserAgent    string                 `json:"userAgent,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// generateUserID creates a unique user identifier
func generateUserID() string {
	// Generate a unique user ID (could use UUID or other method)
	return fmt.Sprintf("user_%d", time.Now().UnixNano())
}

// hashString creates a SHA-256 hex digest (used for channelHash)
func hashString(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// makeChannelKey creates a unique composite key for UserChannels
func makeChannelKey(userID, channelType, channelHash string) string {
	return fmt.Sprintf("%s|%s|%s", userID, channelType, channelHash)
}

// tokenizePII handles PII tokenization via internal/pii service
func tokenizePII(req PIITokenizationRequest) (*PIITokenizationResponse, error) {
	// TODO: Integrate with internal/pii service for ISO-compliant tokenization
	// For now, return placeholder tokens
	tokens := map[string]string{
		"firstName": fmt.Sprintf("tok_fn_%d", time.Now().UnixNano()),
		"lastName":  fmt.Sprintf("tok_ln_%d", time.Now().UnixNano()),
	}
	
	if req.Email != "" {
		tokens["email"] = fmt.Sprintf("tok_em_%d", time.Now().UnixNano())
	}
	
	if req.Phone != "" {
		tokens["phone"] = fmt.Sprintf("tok_ph_%d", time.Now().UnixNano())
	}
	
	return &PIITokenizationResponse{
		Tokens: tokens,
		Status: "success",
	}, nil
}

// triggerIdentityCheck initiates identity verification via JanusFace
func triggerIdentityCheck(userID string) (string, error) {
	// TODO: Integrate with JanusFace agent for identity enrollment
	// For now, return placeholder identity check ID
	identityCheckID := fmt.Sprintf("id_check_%s_%d", userID, time.Now().UnixNano())
	
	// Debug: fmt.Printf("🔍 Identity check initiated: %s for user %s\n", identityCheckID, userID)
	return identityCheckID, nil
}

// emitAuditEvent creates an ISO-compliant audit trail entry
func emitAuditEvent(event AuditEvent) (string, error) {
    // Build details payload including metadata and masked IP (no raw UA to avoid duplication)
    details := map[string]interface{}{
        "metadata": event.Metadata,
    }
    if event.IPAddress != "" {
        if masked := maskIP(event.IPAddress); masked != "" {
            details["ipMasked"] = masked
        }
    }

    return audit.Log(audit.EntryParams{
        Category:    "AUTHENTICATION",
        Action:      "USER_REGISTERED",
        ObjectType:  "User",
        ObjectID:    event.UserID,
        PerformedBy: "HecateRegister",
        Source:      "HecateRegister",
        Severity:    "INFO",
        Timestamp:   event.Timestamp,
        Details:     details,
        IPAddress:   event.IPAddress, // used to derive ipHash predicate only
        UserAgentRaw: event.UserAgent, // normalized and linked via userAgent edge
    })
}

// maskIP returns a privacy-preserving masked IP string for audit details
// IPv4: mask to /24 (zero last octet). IPv6: mask to /64 (zero last 8 bytes).
func maskIP(ipStr string) string {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return ""
    }
    if v4 := ip.To4(); v4 != nil {
        masked := make([]byte, len(v4))
        copy(masked, v4)
        masked[3] = 0
        return net.IP(masked).String()
    }
    v6 := ip.To16()
    if v6 == nil {
        return ""
    }
    masked := make([]byte, len(v6))
    copy(masked, v6)
    for i := 8; i < 16; i++ {
        masked[i] = 0
    }
    return net.IP(masked).String()
}

// isFirstUser determines if there are currently zero users in the graph
func isFirstUser() (bool, error) {
    query := `{
        u(func: type(User), first: 1) { uid }
    }`
    result, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(query))
    if err != nil {
        return false, fmt.Errorf("failed to query users: %v", err)
    }
    var resp struct {
        U []struct{ UID string `json:"uid"` } `json:"u"`
    }
    if result.Json == "" {
        return true, nil
    }
    if err := json.Unmarshal([]byte(result.Json), &resp); err != nil {
        return false, fmt.Errorf("failed to parse users query: %v", err)
    }
    return len(resp.U) == 0, nil
}

// getRoleUID fetches a Role UID by roleKey; if missing, attempts to create it
func getRoleUID(roleKey, name string) (string, error) {
    query := fmt.Sprintf(`{ r(func: eq(roleKey, %q)) { uid } }`, roleKey)
    result, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(query))
    if err != nil {
        return "", fmt.Errorf("failed to query role %s: %v", roleKey, err)
    }
    var resp struct {
        R []struct{ UID string `json:"uid"` } `json:"r"`
    }
    if result.Json != "" {
        if err := json.Unmarshal([]byte(result.Json), &resp); err != nil {
            return "", fmt.Errorf("failed to parse role query: %v", err)
        }
        if len(resp.R) > 0 {
            return resp.R[0].UID, nil
        }
    }
    // Create role if not found
    nquads := fmt.Sprintf(`
        _:role <dgraph.type> "Role" .
        _:role <name> %q .
        _:role <roleKey> %q .
    `, name, roleKey)
    mut := dgraph.NewMutation().WithSetNquads(nquads)
    res, err := dgraph.ExecuteMutations("dgraph", mut)
    if err != nil {
        return "", fmt.Errorf("failed to create role %s: %v", roleKey, err)
    }
    if uid, ok := res.Uids["role"]; ok {
        return uid, nil
    }
    return "", fmt.Errorf("role created but UID not returned for %s", roleKey)
}

// createUserInDgraph stores the new user record in Dgraph
func createUserInDgraph(req UserRegistrationRequest, userID string, roleUIDs []string) error {
	// Validate channel type
	switch req.ChannelType {
	case "email", "phone":
		// ok
	default:
		return fmt.Errorf("unsupported channel type: %s", req.ChannelType)
	}

	now := time.Now()
	chHash := hashString(req.Recipient)
	chKey := makeChannelKey(userID, req.ChannelType, chHash)

	// Build N-Quads for User and UserChannels aligned with schema
	nquads := fmt.Sprintf(`
		_:user <dgraph.type> "User" .
		_:user <did> %q .
		_:user <status> "active" .
		_:user <createdAt> "%s"^^<xs:dateTime> .
		_:user <updatedAt> "%s"^^<xs:dateTime> .

		_:channel <dgraph.type> "UserChannels" .
		_:channel <user> _:user .
		_:channel <userId> %q .
		_:channel <channelType> %q .
		_:channel <channelHash> %q .
		_:channel <channelKey> %q .
		_:channel <verified> "true"^^<xs:boolean> .
		_:channel <primary> "true"^^<xs:boolean> .
		_:channel <createdAt> "%s"^^<xs:dateTime> .
		_:channel <lastUsedAt> "%s"^^<xs:dateTime> .
	`,
		userID,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
		userID,
		req.ChannelType,
		chHash,
		chKey,
		now.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)

	// Link roles if provided
	for _, rid := range roleUIDs {
		nquads += fmt.Sprintf("\n        _:user <roles> <%s> .\n", rid)
	}

	// Execute mutation using Dgraph SDK
	mutationObj := dgraph.NewMutation().WithSetNquads(nquads)
	result, err := dgraph.ExecuteMutations("dgraph", mutationObj)
	if err != nil {
		return fmt.Errorf("failed to create user in Dgraph: %v", err)
	}

	// Optionally use returned UIDs
	if len(result.Uids) > 0 {
		if uid, ok := result.Uids["user"]; ok {
			_ = uid
		}
		if cuid, ok := result.Uids["channel"]; ok {
			_ = cuid
		}
	}

	return nil
}

// RegisterUser is the main exported function to register a new user
func RegisterUser(ctx context.Context, req UserRegistrationRequest) (UserRegistrationResponse, error) {
	// Debug: fmt.Printf("🌙 HecateRegister: Initiating user registration for %s\n", req.Recipient)
	
	// Generate unique user ID
	userID := generateUserID()
	
	// Step 1: PII Tokenization for ISO compliance
	piiReq := PIITokenizationRequest{
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}
	
	switch req.ChannelType {
	case "email":
		piiReq.Email = req.Recipient
	case "phone":
		piiReq.Phone = req.Recipient
	}
	
	piiResp, err := tokenizePII(piiReq)
	if err != nil {
		return UserRegistrationResponse{
			Success: false,
			Message: "Failed to tokenize PII data",
		}, fmt.Errorf("PII tokenization failed: %v", err)
	}
	
	// Step 2a: Determine roles
	isFirst, err := isFirstUser()
	if err != nil {
		fmt.Printf("⚠️ Failed to check first user: %v\n", err)
	}
	var roleUIDs []string
	if isFirst {
		if uid, rerr := getRoleUID("default|superadmin", "superadmin"); rerr == nil && uid != "" {
			roleUIDs = append(roleUIDs, uid)
		} else {
			fmt.Printf("⚠️ Superadmin role missing and could not be created: %v\n", rerr)
		}
	} else {
		if uid, rerr := getRoleUID("default|registered", "registered"); rerr == nil && uid != "" {
			roleUIDs = append(roleUIDs, uid)
		} else {
			fmt.Printf("⚠️ Registered role missing and could not be created: %v\n", rerr)
		}
	}

	// Step 2b: Create user record in Dgraph with roles
	if err := createUserInDgraph(req, userID, roleUIDs); err != nil {
		return UserRegistrationResponse{
			Success: false,
			Message: "Failed to create user account",
		}, fmt.Errorf("user creation failed: %v", err)
	}
	
	// Step 3: Trigger identity verification
	identityCheckID, err := triggerIdentityCheck(userID)
	if err != nil {
		fmt.Printf("⚠️ Identity check failed (non-critical): %v\n", err)
		// Don't fail registration if identity check fails
	}
	
	// Step 4: Emit audit event for ISO compliance
    // Compute UTC and best-effort local time based on requested timezone
    utcNow := time.Now().UTC()
    tzName := req.Timezone
    loc, lerr := time.LoadLocation(tzName)
    if lerr != nil || loc == nil {
        loc = time.UTC
        if tzName == "" {
            tzName = "UTC"
        }
    }
    localNow := utcNow.In(loc)
    _, offset := localNow.Zone()

    // Build metadata, merging client-provided req.Metadata
    meta := map[string]interface{}{
        "channelType":            req.ChannelType,
        "channelDID":             req.ChannelDID,
        "registrationSource":     "HecateRegister",
        "piiTokenized":           true,
        "identityCheckID":        identityCheckID,
        "timezone":               tzName,
        "language":               req.Language,
        "localTime":              localNow.Format(time.RFC3339),
        "timestampUTC":           utcNow.Format(time.RFC3339),
        "timezoneOffsetMinutes":  offset / 60,
    }
    if req.Metadata != nil {
        for k, v := range req.Metadata {
            // client-provided metadata keys override if duplicated
            meta[k] = v
        }
    }

    auditEvent := AuditEvent{
        EventType: "UserRegistered",
        UserID:    userID,
        Timestamp: utcNow,
        IPAddress: req.IPAddress,
        UserAgent: req.UserAgent,
        Metadata:  meta,
    }
	
	auditEventID, err := emitAuditEvent(auditEvent)
	if err != nil {
		fmt.Printf("⚠️ Audit event failed (non-critical): %v\n", err)
		// Don't fail registration if audit fails
	}
	
	// Return successful registration response
	return UserRegistrationResponse{
		Success:         true,
		UserID:          userID,
		Message:         "User registration completed successfully",
		PIITokens:       piiResp.Tokens,
		IdentityCheckID: identityCheckID,
		AuditEventID:    auditEventID,
		CreatedAt:       time.Now(),
	}, nil
}
