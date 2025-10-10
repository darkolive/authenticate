package Persona

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	vcrypto "backend/services/vault"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// GetPIIRequest requests decrypted persona fields for a user.
// This should only be invoked for the data subject on secure server paths.
type GetPIIRequest struct {
	UserID string `json:"userID"`
}

// GetPIIResponse returns decrypted and stored (ciphertext) variants.
// Plaintext fields are populated only if corresponding ciphertext exists and decryption succeeds.
// Ciphertext is returned for transparency/diagnostics; do not render by default to non-owners.
type GetPIIResponse struct {
	FirstName    string `json:"firstName,omitempty"`
	LastName     string `json:"lastName,omitempty"`
	DisplayName  string `json:"displayName,omitempty"`
	FirstNameEnc string `json:"firstName_enc,omitempty"`
	LastNameEnc  string `json:"lastName_enc,omitempty"`
	DisplayNameEnc string `json:"displayName_enc,omitempty"`
	Message      string `json:"message,omitempty"`
}

// GetUserPII loads encrypted persona fields and decrypts them via Vault transit.
func GetUserPII(_ context.Context, req GetPIIRequest) (GetPIIResponse, error) {
	if strings.TrimSpace(req.UserID) == "" {
		return GetPIIResponse{Message: "userID is required"}, nil
	}
	uid, err := getUserUIDByDID(req.UserID)
	if err != nil {
		return GetPIIResponse{Message: "user not found"}, nil
	}
	q := fmt.Sprintf(`{
		u(func: uid(%s)) {
			firstName_enc
			lastName_enc
			displayName_enc
		}
	}`, uid)
	res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
	if qerr != nil {
		return GetPIIResponse{Message: fmt.Sprintf("query failed: %v", qerr)}, nil
	}
	var parsed struct {
		U []struct {
			FirstNameEnc   string `json:"firstName_enc"`
			LastNameEnc    string `json:"lastName_enc"`
			DisplayNameEnc string `json:"displayName_enc"`
		} `json:"u"`
	}
	if res.Json == "" {
		return GetPIIResponse{Message: "no data"}, nil
	}
	_ = json.Unmarshal([]byte(res.Json), &parsed)
	if len(parsed.U) == 0 {
		return GetPIIResponse{Message: "user not found"}, nil
	}
	row := parsed.U[0]
	out := GetPIIResponse{
		FirstNameEnc:    strings.TrimSpace(row.FirstNameEnc),
		LastNameEnc:     strings.TrimSpace(row.LastNameEnc),
		DisplayNameEnc:  strings.TrimSpace(row.DisplayNameEnc),
	}
	// Decrypt best-effort; partial success allowed.
	if out.FirstNameEnc != "" {
		if pt, derr := vcrypto.Decrypt("pii-identity", out.FirstNameEnc); derr == nil {
			out.FirstName = string(pt)
		}
	}
	if out.LastNameEnc != "" {
		if pt, derr := vcrypto.Decrypt("pii-identity", out.LastNameEnc); derr == nil {
			out.LastName = string(pt)
		}
	}
	if out.DisplayNameEnc != "" {
		if pt, derr := vcrypto.Decrypt("pii-identity", out.DisplayNameEnc); derr == nil {
			out.DisplayName = string(pt)
		}
	}
	return out, nil
}
