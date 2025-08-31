package ChronosSession

import (
	"context"
	"fmt"
)

// Integration uses SESSION_TYPE constants from types.go

// AuthResult represents the result of authentication from various agents
type AuthResult struct {
	UserID        string
	ChannelDID    string
	AuthType      string
	AdditionalInfo map[string]interface{}
	IPAddress     string
	UserAgent     string
	DeviceInfo    string
}

// CreateSessionFromAuth creates a session from successful authentication
func CreateSessionFromAuth(ctx context.Context, authResult *AuthResult) (*SessionResponse, error) {
	// Initialize ChronosSession
	chronos, err := Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ChronosSession: %w", err)
	}

	// Prepare session request
	req := &SessionRequest{
		UserID: authResult.UserID,
		AdditionalClaims: map[string]interface{}{
			"auth_type":   authResult.AuthType,
			"channel_did": authResult.ChannelDID,
		},
		DeviceInfo: authResult.DeviceInfo,
		IPAddress:  authResult.IPAddress,
		UserAgent:  authResult.UserAgent,
	}

	// Add any additional info to claims
	for k, v := range authResult.AdditionalInfo {
		if _, exists := req.AdditionalClaims[k]; !exists {
			req.AdditionalClaims[k] = v
		}
	}

	// Issue the session
	return chronos.IssueSession(ctx, req)
}

// ValidateSessionToken validates a session token and returns user information
func ValidateSessionToken(ctx context.Context, token string) (*ValidationResponse, error) {
	// Initialize ChronosSession
	chronos, err := Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ChronosSession: %w", err)
	}

	// Create validation request
	req := &ValidationRequest{
		Token: token,
	}

	// Validate the session
	return chronos.ValidateSession(ctx, req)
}

// RefreshSessionToken refreshes a session token if it's eligible
func RefreshSessionToken(ctx context.Context, token string) (*SessionResponse, error) {
	// Initialize ChronosSession
	chronos, err := Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ChronosSession: %w", err)
	}

	// Create refresh request
	req := &RefreshRequest{
		Token: token,
	}

	// Refresh the session
	return chronos.RefreshSession(ctx, req)
}

// RevokeSessionToken revokes/invalidates a session token
func RevokeSessionToken(ctx context.Context, token string, reason string) (*RevocationResponse, error) {
	// Initialize ChronosSession
	chronos, err := Initialize()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ChronosSession: %w", err)
	}

	// Create revocation request
	req := &RevocationRequest{
		Token:  token,
		Reason: reason,
	}

	// Revoke the session
	return chronos.RevokeSession(ctx, req)
}
