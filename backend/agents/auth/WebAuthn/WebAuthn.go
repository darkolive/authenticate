package WebAuthn

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"backend/agents/audit"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// Request/response types exposed via GraphQL

type BeginRegistrationRequest struct {
	UserID      string `json:"userID"`
	DisplayName string `json:"displayName,omitempty"`
	IPAddress   string `json:"ipAddress,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
}

type BeginRegistrationResponse struct {
	OptionsJSON string `json:"optionsJSON"`
	Challenge  string `json:"challenge"`
	ExpiresAt  string `json:"expiresAt"`
}

type FinishRegistrationRequest struct {
	UserID         string `json:"userID"`
	Challenge      string `json:"challenge"`
	CredentialJSON string `json:"credentialJSON"`
	IPAddress      string `json:"ipAddress,omitempty"`
	UserAgent      string `json:"userAgent,omitempty"`
}

type FinishRegistrationResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	CredentialID string `json:"credentialId,omitempty"`
}

type BeginLoginRequest struct {
	UserID string `json:"userID"`
	IPAddress   string `json:"ipAddress,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
}

type BeginLoginResponse struct {
	OptionsJSON string `json:"optionsJSON"`
	Challenge  string `json:"challenge"`
	ExpiresAt  string `json:"expiresAt"`
}

type FinishLoginRequest struct {
	UserID         string `json:"userID"`
	Challenge      string `json:"challenge"`
	CredentialJSON string `json:"credentialJSON"`
	IPAddress      string `json:"ipAddress,omitempty"`
	UserAgent      string `json:"userAgent,omitempty"`
}

type FinishLoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Helpers

func randomChallenge(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func getUserUIDByDID(userDID string) (string, error) {
	if strings.TrimSpace(userDID) == "" {
		return "", fmt.Errorf("userID is required")
	}
	q := fmt.Sprintf(`{ u(func: eq(did, %q), first: 1) { uid } }`, userDID)
	res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
	if err != nil {
		return "", fmt.Errorf("user lookup failed: %v", err)
	}
	var parsed struct{ U []struct{ UID string `json:"uid"` } `json:"u"` }
	if res.Json != "" {
		_ = json.Unmarshal([]byte(res.Json), &parsed)
	}
	if len(parsed.U) == 0 || parsed.U[0].UID == "" {
		return "", fmt.Errorf("user not found")
	}
	return parsed.U[0].UID, nil
}

func saveChallenge(challenge, userID, typ string, ttlMinutes int) (string, error) {
	now := time.Now().UTC()
	expires := now.Add(time.Duration(ttlMinutes) * time.Minute)
	nquads := fmt.Sprintf(`_:c <dgraph.type> "WebAuthnChallenge" .
_:c <challenge> %q .
_:c <userId> %q .
_:c <type> %q .
_:c <createdAt> %q^^<xs:dateTime> .
_:c <expiresAt> %q^^<xs:dateTime> .`, challenge, userID, typ, now.Format(time.RFC3339), expires.Format(time.RFC3339))
	mu := dgraph.NewMutation().WithSetNquads(nquads)
	if _, err := dgraph.ExecuteMutations("dgraph", mu); err != nil {
		return "", err
	}
	return expires.Format(time.RFC3339), nil
}

// BeginRegistration returns publicKeyCredentialCreationOptions JSON (minimal) and persists a challenge
func BeginRegistration(req BeginRegistrationRequest) (BeginRegistrationResponse, error) {
	if _, err := getUserUIDByDID(req.UserID); err != nil {
		return BeginRegistrationResponse{}, err
	}
	ch, err := randomChallenge(32)
	if err != nil { return BeginRegistrationResponse{}, err }
	// Minimal options JSON (frontend will use standard fields)
	userIDB64 := base64.RawURLEncoding.EncodeToString([]byte(req.UserID))
	opts := map[string]any{
		"challenge": ch,
		"rp": map[string]any{"id": "localhost", "name": "Hypermode Auth"},
		"user": map[string]any{"id": userIDB64, "name": req.UserID, "displayName": firstNonEmpty(req.DisplayName, req.UserID)},
		"pubKeyCredParams": []map[string]any{{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}},
		"timeout": 60000,
	}
	b, _ := json.Marshal(opts)
	exp, err := saveChallenge(ch, req.UserID, "registration", 10)
	if err != nil { return BeginRegistrationResponse{}, err }

	// Audit: WebAuthn registration begin
	utcNow := time.Now().UTC()
	tzName := "UTC"
	localNow := utcNow
	offsetMinutes := 0
	_, _ = audit.Log(audit.EntryParams{
		Category:    "AUTHENTICATION",
		Action:      "WEBAUTHN_REG_BEGIN",
		ObjectType:  "User",
		ObjectID:    req.UserID,
		PerformedBy: "WebAuthn",
		Source:      "WebAuthn",
		Severity:    "INFO",
		Details: map[string]interface{}{
			"challenge":             ch,
			"timezone":              tzName,
			"localTime":             localNow.Format(time.RFC3339),
			"timestampUTC":          utcNow.Format(time.RFC3339),
			"timezoneOffsetMinutes": offsetMinutes,
		},
		IPAddress:    req.IPAddress,
		UserAgentRaw: req.UserAgent,
		Timestamp:    utcNow,
	})

	return BeginRegistrationResponse{OptionsJSON: string(b), Challenge: ch, ExpiresAt: exp}, nil
}

// FinishRegistration stores a credential skeleton (verification to be added)
func FinishRegistration(req FinishRegistrationRequest) (FinishRegistrationResponse, error) {
	userUID, err := getUserUIDByDID(req.UserID)
	if err != nil {
		return FinishRegistrationResponse{Success: false, Message: "user not found"}, nil
	}
	if strings.TrimSpace(req.CredentialJSON) == "" || strings.TrimSpace(req.Challenge) == "" {
		return FinishRegistrationResponse{Success: false, Message: "missing fields"}, nil
	}
	var payload struct{ ID, RawID string }
	_ = json.Unmarshal([]byte(req.CredentialJSON), &payload)
	credID := strings.TrimSpace(payload.RawID)
	if credID == "" { credID = strings.TrimSpace(payload.ID) }
	if credID == "" { return FinishRegistrationResponse{Success: false, Message: "invalid credential"}, nil }
	// Idempotent: ensure not existing, otherwise create and link to user
	// Check existing
	q := fmt.Sprintf(`{ c(func: eq(credentialId, %q), first: 1) { uid } }`, credID)
	if res, _ := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q)); res.Json != "" {
		var parsed struct{ C []struct{ UID string `json:"uid"` } `json:"c"` }
		_ = json.Unmarshal([]byte(res.Json), &parsed)
		if len(parsed.C) > 0 && parsed.C[0].UID != "" {
			return FinishRegistrationResponse{Success: true, Message: "credential already registered", CredentialID: credID}, nil
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	nq := fmt.Sprintf(`_:k <dgraph.type> "WebAuthnCredential" .
_:k <credentialId> %q .
_:k <signCount> "0"^^<xs:int> .
_:k <addedAt> %q^^<xs:dateTime> .
_:k <user> <%s> .`, credID, now, userUID)
	var transports string
	if strings.Contains(req.CredentialJSON, "transports") {
		var cred struct{ Transports []string `json:"transports"` }
		_ = json.Unmarshal([]byte(req.CredentialJSON), &cred)
		transports = strings.Join(cred.Transports, ",")
	}
	if transports != "" { nq += "\n_:k <transports> \"" + transports + "\" ." }
	mu := dgraph.NewMutation().WithSetNquads(nq)
	if _, err := dgraph.ExecuteMutations("dgraph", mu); err != nil {
		return FinishRegistrationResponse{Success: false, Message: fmt.Sprintf("store failed: %v", err)}, nil
	}

	// Audit: WebAuthn registration finish
	utcNow := time.Now().UTC()
	tzName := "UTC"
	localNow := utcNow
	offsetMinutes := 0
	_, _ = audit.Log(audit.EntryParams{
		Category:    "AUTHENTICATION",
		Action:      "WEBAUTHN_REG_FINISH",
		ObjectType:  "User",
		ObjectID:    req.UserID,
		PerformedBy: "WebAuthn",
		Source:      "WebAuthn",
		Severity:    "INFO",
		Details: map[string]interface{}{
			"credentialId":          credID,
			"timezone":              tzName,
			"localTime":             localNow.Format(time.RFC3339),
			"timestampUTC":          utcNow.Format(time.RFC3339),
			"timezoneOffsetMinutes": offsetMinutes,
		},
		IPAddress:    req.IPAddress,
		UserAgentRaw: req.UserAgent,
		Timestamp:    utcNow,
	})

	return FinishRegistrationResponse{Success: true, Message: "registered", CredentialID: credID}, nil
}

// BeginLogin returns publicKeyCredentialRequestOptions JSON and persists a challenge
func BeginLogin(req BeginLoginRequest) (BeginLoginResponse, error) {
	userUID, err := getUserUIDByDID(req.UserID)
	if err != nil { return BeginLoginResponse{}, err }
	ch, err := randomChallenge(32)
	if err != nil { return BeginLoginResponse{}, err }
	// Allowed credentials for user (optional)
	q := fmt.Sprintf(`{ u(func: uid(%s)) { creds: ~user @filter(type(WebAuthnCredential)) { credentialId } } }`, userUID)
	res, _ := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
	var allow []map[string]any
	if res.Json != "" {
		var parsed struct { U []struct { Creds []struct{ ID string `json:"credentialId"` } `json:"creds"` } `json:"u"` }
		_ = json.Unmarshal([]byte(res.Json), &parsed)
		if len(parsed.U) > 0 {
			for _, c := range parsed.U[0].Creds { if c.ID != "" { allow = append(allow, map[string]any{"type": "public-key", "id": c.ID}) } }
		}
	}
	opts := map[string]any{
		"challenge": ch,
		"rpId": "localhost",
	}
	if len(allow) > 0 { opts["allowCredentials"] = allow }
	b, _ := json.Marshal(opts)
	exp, err := saveChallenge(ch, req.UserID, "authentication", 5)
	if err != nil { return BeginLoginResponse{}, err }

	// Audit: WebAuthn login begin
	utcNow := time.Now().UTC()
	tzName := "UTC"
	localNow := utcNow
	offsetMinutes := 0
	_, _ = audit.Log(audit.EntryParams{
		Category:    "AUTHENTICATION",
		Action:      "WEBAUTHN_LOGIN_BEGIN",
		ObjectType:  "User",
		ObjectID:    req.UserID,
		PerformedBy: "WebAuthn",
		Source:      "WebAuthn",
		Severity:    "INFO",
		Details: map[string]interface{}{
			"challenge":             ch,
			"timezone":              tzName,
			"localTime":             localNow.Format(time.RFC3339),
			"timestampUTC":          utcNow.Format(time.RFC3339),
			"timezoneOffsetMinutes": offsetMinutes,
		},
		IPAddress:    req.IPAddress,
		UserAgentRaw: req.UserAgent,
		Timestamp:    utcNow,
	})

	return BeginLoginResponse{OptionsJSON: string(b), Challenge: ch, ExpiresAt: exp}, nil
}

// FinishLogin does a shallow check (existence). Full cryptographic verification TODO.
func FinishLogin(req FinishLoginRequest) (FinishLoginResponse, error) {
	if _, err := getUserUIDByDID(req.UserID); err != nil {
		return FinishLoginResponse{Success: false, Message: "user not found"}, nil
	}
	if strings.TrimSpace(req.CredentialJSON) == "" || strings.TrimSpace(req.Challenge) == "" {
		return FinishLoginResponse{Success: false, Message: "missing fields"}, nil
	}
	var payload struct{ ID, RawID string }
	_ = json.Unmarshal([]byte(req.CredentialJSON), &payload)
	credID := strings.TrimSpace(payload.RawID)
	if credID == "" { credID = strings.TrimSpace(payload.ID) }
	if credID == "" { return FinishLoginResponse{Success: false, Message: "invalid credential"}, nil }
	// Check credential exists
	q := fmt.Sprintf(`{ c(func: eq(credentialId, %q), first: 1) { uid } }`, credID)
	res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
	if err != nil || res.Json == "" { return FinishLoginResponse{Success: false, Message: "credential not found"}, nil }

	// Audit: WebAuthn login finish
	utcNow := time.Now().UTC()
	tzName := "UTC"
	localNow := utcNow
	offsetMinutes := 0
	_, _ = audit.Log(audit.EntryParams{
		Category:    "AUTHENTICATION",
		Action:      "WEBAUTHN_LOGIN_FINISH",
		ObjectType:  "User",
		ObjectID:    req.UserID,
		PerformedBy: "WebAuthn",
		Source:      "WebAuthn",
		Severity:    "INFO",
		Details: map[string]interface{}{
			"credentialId":          credID,
			"timezone":              tzName,
			"localTime":             localNow.Format(time.RFC3339),
			"timestampUTC":          utcNow.Format(time.RFC3339),
			"timezoneOffsetMinutes": offsetMinutes,
		},
		IPAddress:    req.IPAddress,
		UserAgentRaw: req.UserAgent,
		Timestamp:    utcNow,
	})

	return FinishLoginResponse{Success: true, Message: "authenticated (verification TODO)"}, nil
}

func firstNonEmpty(vals ...string) string { for _, v := range vals { if strings.TrimSpace(v) != "" { return v } } ; return "" }
