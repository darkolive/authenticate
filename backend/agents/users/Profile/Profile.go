package Profile

import (
    "context"
    "encoding/json"
    "fmt"
    "strings"
    "time"

    "backend/agents/audit"
    "github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// UpdateProfileRequest contains profile fields to persist for a user
// The user is identified by their DID stored in the User.did predicate
// (this DID corresponds to the userID used across the app)
type UpdateProfileRequest struct {
    UserID      string `json:"userID"`
    FirstName   string `json:"firstName,omitempty"`
    LastName    string `json:"lastName,omitempty"`
    DisplayName string `json:"displayName,omitempty"`
    IPAddress   string `json:"ipAddress,omitempty"`
    UserAgent   string `json:"userAgent,omitempty"`
}

// UpdateProfileResponse is returned after updating the user's profile
type UpdateProfileResponse struct {
    Success   bool   `json:"success"`
    Message   string `json:"message,omitempty"`
    UserID    string `json:"userID,omitempty"`
    UpdatedAt string `json:"updatedAt,omitempty"`
}

// ProfileCompleteRequest asks if a user's profile is complete
// A profile is considered complete if either displayName or name is set
// (name can be a concatenation of first/last names)
type ProfileCompleteRequest struct {
    UserID string `json:"userID"`
}

// ProfileCompleteResponse indicates the completeness state for gating
type ProfileCompleteResponse struct {
    Complete       bool   `json:"complete"`
    HasDisplayName bool   `json:"hasDisplayName"`
    HasName        bool   `json:"hasName"`
    Status         string `json:"status,omitempty"`
    Message        string `json:"message,omitempty"`
}

// UpdateUserProfile updates a user's displayName and/or name predicates
// and refreshes updatedAt. The user is located via did == UserID.
func UpdateUserProfile(_ context.Context, req UpdateProfileRequest) (UpdateProfileResponse, error) {
    uid, err := getUserUIDByDID(req.UserID)
    if err != nil {
        return UpdateProfileResponse{Success: false, Message: "user not found"}, nil
    }

    // Fetch pre-update profile flags to compare and include in audit details
    var beforeDisplayName, beforeName string
    {
        q := fmt.Sprintf(`{
        u(func: uid(%s)) {
            displayName
            name
        }
    }`, uid)
        res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
        if qerr == nil && res.Json != "" {
            var parsed struct {
                U []struct {
                    DisplayName string `json:"displayName"`
                    Name        string `json:"name"`
                } `json:"u"`
            }
            _ = json.Unmarshal([]byte(res.Json), &parsed)
            if len(parsed.U) > 0 {
                beforeDisplayName = strings.TrimSpace(parsed.U[0].DisplayName)
                beforeName = strings.TrimSpace(parsed.U[0].Name)
            }
        }
    }
    beforeHasDN := beforeDisplayName != ""
    beforeHasNM := beforeName != ""
    beforeComplete := beforeHasDN || beforeHasNM

    fullName := strings.TrimSpace(strings.TrimSpace(req.FirstName) + " " + strings.TrimSpace(req.LastName))
    updatedAt := time.Now().UTC().Format(time.RFC3339)
    displayNameTrim := strings.TrimSpace(req.DisplayName)

    // Build N-Quads update for existing user node
    nquads := fmt.Sprintf("<%s> <updatedAt> %q^^<http://www.w3.org/2001/XMLSchema#dateTime> .", uid, updatedAt)
    updatedFields := []string{}
    if fullName != "" {
        nquads += fmt.Sprintf("\n<%s> <name> %q .", uid, fullName)
        if fullName != beforeName {
            updatedFields = append(updatedFields, "name")
        }
    }
    if displayNameTrim != "" {
        nquads += fmt.Sprintf("\n<%s> <displayName> %q .", uid, displayNameTrim)
        if displayNameTrim != beforeDisplayName {
            updatedFields = append(updatedFields, "displayName")
        }
    }

    mu := dgraph.NewMutation().WithSetNquads(nquads)
    if _, err := dgraph.ExecuteMutations("dgraph", mu); err != nil {
        return UpdateProfileResponse{Success: false, Message: fmt.Sprintf("update failed: %v", err)}, nil
    }

    // Compute after-update flags for audit (assume fields unchanged if not set)
    afterHasDN := beforeHasDN
    if displayNameTrim != "" {
        afterHasDN = true
    }
    afterHasNM := beforeHasNM
    if fullName != "" {
        afterHasNM = true
    }
    afterComplete := afterHasDN || afterHasNM

    // Emit audit event (best-effort; failures do not affect response)
    if len(updatedFields) > 0 {
        _, _ = audit.Log(audit.EntryParams{
            Category:     "PROFILE",
            Action:       "PROFILE_UPDATED",
            ObjectType:   "User",
            ObjectID:     req.UserID,
            PerformedBy:  "Profile",
            Source:       "UpdateUserProfile",
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

    return UpdateProfileResponse{Success: true, Message: "profile updated", UserID: req.UserID, UpdatedAt: updatedAt}, nil
}

// IsProfileComplete checks whether the user has sufficient profile fields set
func IsProfileComplete(req ProfileCompleteRequest) (ProfileCompleteResponse, error) {
    uid, err := getUserUIDByDID(req.UserID)
    if err != nil {
        return ProfileCompleteResponse{Complete: false, Message: "user not found"}, nil
    }

    q := fmt.Sprintf(`{
        u(func: uid(%s)) {
            displayName
            name
            status
        }
    }`, uid)

    res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if qerr != nil {
        return ProfileCompleteResponse{Complete: false, Message: fmt.Sprintf("query failed: %v", qerr)}, nil
    }

    var parsed struct {
        U []struct {
            DisplayName string `json:"displayName"`
            Name        string `json:"name"`
            Status      string `json:"status"`
        } `json:"u"`
    }
    if res.Json != "" {
        _ = json.Unmarshal([]byte(res.Json), &parsed)
    }
    if len(parsed.U) == 0 {
        return ProfileCompleteResponse{Complete: false, Message: "user not found"}, nil
    }

    dn := strings.TrimSpace(parsed.U[0].DisplayName)
    nm := strings.TrimSpace(parsed.U[0].Name)
    hasDN := dn != ""
    hasNM := nm != ""
    complete := hasDN || hasNM

    return ProfileCompleteResponse{
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
