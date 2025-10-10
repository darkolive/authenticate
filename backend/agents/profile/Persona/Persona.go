package Persona

import (
    "context"
    "encoding/json"
    "fmt"
    "strings"
    "time"

    audit "backend/agents/audit/ThemisLog"
    vcrypto "backend/services/vault"

    "github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// UpdatepersonaRequest contains persona fields to persist for a user
// The user is identified by their DID stored in the User.did predicate
// (this DID corresponds to the userID used across the app)
type UpdatepersonaRequest struct {
    UserID      string `json:"userID"`
    FirstName   string `json:"firstName,omitempty"`
    LastName    string `json:"lastName,omitempty"`
    DisplayName string `json:"displayName,omitempty"`
    IPAddress   string `json:"ipAddress,omitempty"`
    UserAgent   string `json:"userAgent,omitempty"`
}

// UpdatepersonaResponse is returned after updating the user's persona
type UpdatepersonaResponse struct {
    Success   bool   `json:"success"`
    Message   string `json:"message,omitempty"`
    UserID    string `json:"userID,omitempty"`
    UpdatedAt string `json:"updatedAt,omitempty"`
}

// CompletepersonaRequest asks if a user's persona is complete
// A persona is considered complete if either displayName or name is set
// (name can be a concatenation of first/last names)
type CompletepersonaRequest struct {
    UserID string `json:"userID"`
}

// CompletepersonaResponse indicates the completeness state for gating
type CompletepersonaResponse struct {
    Complete       bool   `json:"complete"`
    HasDisplayName bool   `json:"hasDisplayName"`
    HasName        bool   `json:"hasName"`
    Status         string `json:"status,omitempty"`
    Message        string `json:"message,omitempty"`
}

// UpdateUserpersona updates a user's displayName and/or name predicates
// and refreshes updatedAt. The user is located via did == UserID.
func UpdateUserpersona(_ context.Context, req UpdatepersonaRequest) (UpdatepersonaResponse, error) {
    uid, err := getUserUIDByDID(req.UserID)
    if err != nil {
        return UpdatepersonaResponse{Success: false, Message: "user not found"}, nil
    }

    // Fetch pre-update persona flags to compare and include in audit details (encrypted presence only)
    var beforeHasDisplayName, beforeHasName bool
    {
        q := fmt.Sprintf(`{
        u(func: uid(%s)) {
            firstName_enc
            lastName_enc
            displayName_enc
        }
    }`, uid)
        res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
        if qerr == nil && res.Json != "" {
            var parsed struct {
                U []struct {
                    FirstNameEnc   string `json:"firstName_enc"`
                    LastNameEnc    string `json:"lastName_enc"`
                    DisplayNameEnc string `json:"displayName_enc"`
                } `json:"u"`
            }
            _ = json.Unmarshal([]byte(res.Json), &parsed)
            if len(parsed.U) > 0 {
                beforeHasDisplayName = strings.TrimSpace(parsed.U[0].DisplayNameEnc) != ""
                // name completeness if any of first/last present
                if strings.TrimSpace(parsed.U[0].FirstNameEnc) != "" || strings.TrimSpace(parsed.U[0].LastNameEnc) != "" {
                    beforeHasName = true
                }
            }
        }
    }
    beforeHasDN := beforeHasDisplayName
    beforeHasNM := beforeHasName
    beforeComplete := beforeHasDN || beforeHasNM

    updatedAt := time.Now().UTC().Format(time.RFC3339)
    displayNameTrim := strings.TrimSpace(req.DisplayName)
    firstTrim := strings.TrimSpace(req.FirstName)
    lastTrim := strings.TrimSpace(req.LastName)

    // Normalize for blind index (lowercase + trim)
    norm := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

    // Build N-Quads update for existing user node
    nquads := fmt.Sprintf("<%s> <updatedAt> %q^^<http://www.w3.org/2001/XMLSchema#dateTime> .", uid, updatedAt)
    updatedFields := []string{}

    // Encrypt and store persona fields (no plaintext)
    if firstTrim != "" {
        if ct, e := vcrypto.Encrypt("pii-identity", []byte(firstTrim)); e == nil {
            nquads += fmt.Sprintf("\n<%s> <firstName_enc> %q .", uid, ct)
            if bi, herr := vcrypto.HMAC("pii-identity-hmac", []byte(norm(firstTrim))); herr == nil {
                nquads += fmt.Sprintf("\n<%s> <firstName_bi> %q .", uid, bi)
            }
            updatedFields = append(updatedFields, "firstName_enc")
        } else {
            // best-effort: do not fail hard, but include error in message later if all fields fail
        }
    }
    if lastTrim != "" {
        if ct, e := vcrypto.Encrypt("pii-identity", []byte(lastTrim)); e == nil {
            nquads += fmt.Sprintf("\n<%s> <lastName_enc> %q .", uid, ct)
            if bi, herr := vcrypto.HMAC("pii-identity-hmac", []byte(norm(lastTrim))); herr == nil {
                nquads += fmt.Sprintf("\n<%s> <lastName_bi> %q .", uid, bi)
            }
            updatedFields = append(updatedFields, "lastName_enc")
        } else {
        }
    }
    if displayNameTrim != "" {
        if ct, e := vcrypto.Encrypt("pii-identity", []byte(displayNameTrim)); e == nil {
            nquads += fmt.Sprintf("\n<%s> <displayName_enc> %q .", uid, ct)
            if bi, herr := vcrypto.HMAC("pii-identity-hmac", []byte(norm(displayNameTrim))); herr == nil {
                nquads += fmt.Sprintf("\n<%s> <displayName_bi> %q .", uid, bi)
            }
            updatedFields = append(updatedFields, "displayName_enc")
        } else {
        }
    }

    mu := dgraph.NewMutation().WithSetNquads(nquads)
    if _, err := dgraph.ExecuteMutations("dgraph", mu); err != nil {
        return UpdatepersonaResponse{Success: false, Message: fmt.Sprintf("update failed: %v", err)}, nil
    }

    // Compute after-update flags for audit (assume fields unchanged if not set)
    afterHasDN := beforeHasDN
    if displayNameTrim != "" { afterHasDN = true }
    afterHasNM := beforeHasNM
    if firstTrim != "" || lastTrim != "" { afterHasNM = true }
    afterComplete := afterHasDN || afterHasNM

    // Emit audit event (best-effort; failures do not affect response)
    if len(updatedFields) > 0 {
        _, _ = audit.Log(audit.EntryParams{
            Category:     "persona",
            Action:       "persona_UPDATED",
            ObjectType:   "User",
            ObjectID:     req.UserID,
            PerformedBy:  "persona",
            Source:       "UpdateUserpersona",
            Severity:     "INFO",
            Timestamp:    time.Now().UTC(),
            Details: map[string]interface{}{
                "updatedFields": updatedFields,
                "before": map[string]bool{
                    "hasDisplayName": beforeHasDN,
                    "hasName":        beforeHasNM,
                    "complete":       beforeComplete,
                },
                "after": map[string]bool{
                    "hasDisplayName": afterHasDN,
                    "hasName":        afterHasNM,
                    "complete":       afterComplete,
                },
                "updatedAt": updatedAt,
            },
            IPAddress:    req.IPAddress,   // derive ipHash only
            UserAgentRaw: req.UserAgent,   // linked via normalized UserAgent node
        })
    }

    return UpdatepersonaResponse{Success: true, Message: "persona updated", UserID: req.UserID, UpdatedAt: updatedAt}, nil
}

// IspersonaComplete checks whether the user has sufficient persona fields set
func IspersonaComplete(req CompletepersonaRequest) (CompletepersonaResponse, error) {
    uid, err := getUserUIDByDID(req.UserID)
    if err != nil {
        return CompletepersonaResponse{Complete: false, Message: "user not found"}, nil
    }

    q := fmt.Sprintf(`{
        u(func: uid(%s)) {
            displayName_enc
            firstName_enc
            lastName_enc
            status
        }
    }`, uid)

    res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if qerr != nil {
        return CompletepersonaResponse{Complete: false, Message: fmt.Sprintf("query failed: %v", qerr)}, nil
    }

    var parsed struct {
        U []struct {
            DisplayNameEnc string `json:"displayName_enc"`
            FirstNameEnc   string `json:"firstName_enc"`
            LastNameEnc    string `json:"lastName_enc"`
            Status         string `json:"status"`
        } `json:"u"`
    }
    if res.Json != "" {
        _ = json.Unmarshal([]byte(res.Json), &parsed)
    }
    if len(parsed.U) == 0 {
        return CompletepersonaResponse{Complete: false, Message: "user not found"}, nil
    }

    hasDN := strings.TrimSpace(parsed.U[0].DisplayNameEnc) != ""
    hasNM := strings.TrimSpace(parsed.U[0].FirstNameEnc) != "" || strings.TrimSpace(parsed.U[0].LastNameEnc) != ""
    complete := hasDN || hasNM

    return CompletepersonaResponse{
        Complete:       complete,
        HasDisplayName: hasDN,
        HasName:        hasNM,
        Status:         parsed.U[0].Status,
    }, nil
}

// getUserUIDByDID returns the Dgraph UID for a user given their DID (userID)
func getUserUIDByDID(userID string) (string, error) {
    if strings.TrimSpace(userID) == "" {
        return "", fmt.Errorf("userID is required")
    }
    q := fmt.Sprintf(`{ u(func: eq(did, %q), first: 1) { uid } }`, userID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil {
        return "", fmt.Errorf("user lookup failed: %v", err)
    }
    var parsed struct{ U []struct{ UID string `json:"uid"` } `json:"u"` }
    if res.Json != "" {
        _ = json.Unmarshal([]byte(res.Json), &parsed)
    }
    if len(parsed.U) == 0 || strings.TrimSpace(parsed.U[0].UID) == "" {
        return "", fmt.Errorf("user not found")
    }
    return parsed.U[0].UID, nil
}
