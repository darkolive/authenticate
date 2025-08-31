package ChronosSession

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5" // JWT package for token handling
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph" // Correct Modus SDK path with pkg
)

// ChronosSession manages user session lifecycles
type ChronosSession struct {
	secretKey       string
	ttl             int64
	refreshWindow   int64
	sessionRecordType string
}

// Initialize creates a new ChronosSession instance with configuration from env
func Initialize() (*ChronosSession, error) {
	// TEMPORARY FIX: Hardcode configuration values for testing
	// TODO: Fix Modus runtime environment variable loading
	secretKey := "your-secure-secret-key-for-testing-jwt-tokens"
	ttl := int64(86400)      // 24 hours in seconds
	refreshWindow := int64(3600) // 1 hour refresh window
	
	// Debug logging - uncomment for troubleshooting session configuration
	// fmt.Println("✅ Using hardcoded session configuration for testing")
	// fmt.Printf("   SECRET_KEY: %s\n", secretKey[:10]+"...")
	// fmt.Printf("   TTL: %d seconds\n", ttl)
	// fmt.Printf("   REFRESH_WINDOW: %d seconds\n", refreshWindow)

	return &ChronosSession{
		secretKey:       secretKey,
		ttl:             ttl,
		refreshWindow:   refreshWindow,
		sessionRecordType: "AuthSession",
	}, nil
}

// IssueSession creates a new session token for a user
func (cs *ChronosSession) IssueSession(ctx context.Context, req *SessionRequest) (*SessionResponse, error) {
	if req.UserID == "" {
		return nil, errors.New("user ID is required")
	}

	// Set token issuance and expiration times
	now := time.Now()
	expiresAt := now.Add(time.Duration(cs.ttl) * time.Second)

	// Prepare standard claims
	claims := jwt.MapClaims{
		"sub": req.UserID,        // Subject: UserID
		"iat": now.Unix(),        // Issued At: Current time
		"exp": expiresAt.Unix(),  // Expires At: Current time + TTL
		"jti": fmt.Sprintf("%d-%s", now.Unix(), req.UserID), // JWT ID: Unique identifier for this token
	}

	// Add any additional claims
	for k, v := range req.AdditionalClaims {
		if _, exists := claims[k]; !exists { // Don't override standard claims
			claims[k] = v
		}
	}

	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cs.secretKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Store the session in the database
	err = cs.storeSession(ctx, req.UserID, tokenString, now, expiresAt, req)
	if err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	// Emit audit event for session creation (ThemisLog integration point)
	// TODO: Implement audit logging when ThemisLog is available
	// ThemisLog.LogEvent("SessionIssued", map[string]string{"userID": req.UserID})

	// Return the session response
	return &SessionResponse{
		Token:     tokenString,
		ExpiresAt: expiresAt,
		IssuedAt:  now,
		UserID:    req.UserID,
		Message:   "Session created successfully",
	}, nil
}

// ValidateSession validates a session token
func (cs *ChronosSession) ValidateSession(ctx context.Context, req *ValidationRequest) (*ValidationResponse, error) {
	if req.Token == "" {
		return &ValidationResponse{Valid: false, Message: "token is required"}, nil
	}

	// Parse the token
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cs.secretKey), nil
	})

	// Check for parsing errors
	if err != nil {
		return &ValidationResponse{Valid: false, Message: fmt.Sprintf("invalid token: %s", err.Error())}, nil
	}

	// Check if the token is valid
	if !token.Valid {
		return &ValidationResponse{Valid: false, Message: "token is invalid"}, nil
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &ValidationResponse{Valid: false, Message: "invalid claims"}, nil
	}

	// Extract user ID and expiration time
	userID, _ := claims["sub"].(string)
	expFloat, _ := claims["exp"].(float64)
	expiresAt := time.Unix(int64(expFloat), 0)

	// Verify the token hasn't been revoked in the database
	valid, err := cs.isTokenValid(ctx, req.Token)
	if err != nil {
		return &ValidationResponse{Valid: false, Message: fmt.Sprintf("error checking token validity: %s", err.Error())}, nil
	}

	if !valid {
		return &ValidationResponse{Valid: false, Message: "token has been revoked"}, nil
	}

	// Update last used timestamp
	cs.updateLastUsed(ctx, req.Token)

	// Return validation response
	return &ValidationResponse{
		Valid:     true,
		UserID:    userID,
		ExpiresAt: expiresAt,
		Message:   "Token is valid",
	}, nil
}

// RefreshSession extends the lifetime of a valid session
func (cs *ChronosSession) RefreshSession(ctx context.Context, req *RefreshRequest) (*SessionResponse, error) {
	// First validate the token
	validation, err := cs.ValidateSession(ctx, &ValidationRequest{Token: req.Token})
	if err != nil {
		return nil, err
	}

	if !validation.Valid {
		return nil, errors.New(validation.Message)
	}

	// Check if token is within the refresh window
	now := time.Now()
	timeUntilExpiry := validation.ExpiresAt.Sub(now).Seconds()
	
	// Only refresh if token is in the refresh window (approaching expiration)
	// or is past half its lifetime
	if timeUntilExpiry > float64(cs.refreshWindow) && 
	   timeUntilExpiry < float64(cs.ttl/2) {
		return nil, errors.New("token not eligible for refresh yet")
	}

	// Parse the existing token to get the claims
	token, _ := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		return []byte(cs.secretKey), nil
	})
	claims, _ := token.Claims.(jwt.MapClaims)
	
	// Create new session request with the same user ID
	sessionReq := &SessionRequest{
		UserID: validation.UserID,
	}
	
	// Copy additional claims from the original token
	additionalClaims := make(map[string]interface{})
	for key, value := range claims {
		// Skip standard claims
		if key != "sub" && key != "iat" && key != "exp" && key != "jti" {
			additionalClaims[key] = value
		}
	}
	sessionReq.AdditionalClaims = additionalClaims
	
	// Issue a new token
	newSession, err := cs.IssueSession(ctx, sessionReq)
	if err != nil {
		return nil, err
	}
	
	// Revoke the old token
	cs.RevokeSession(ctx, &RevocationRequest{Token: req.Token, Reason: "refreshed"})
	
	return newSession, nil
}

// RevokeSession invalidates a session
func (cs *ChronosSession) RevokeSession(ctx context.Context, req *RevocationRequest) (*RevocationResponse, error) {
	if req.Token == "" {
		return nil, errors.New("token is required")
	}
	
	// Mark the token as invalid in the database
	err := cs.invalidateToken(ctx, req.Token)
	if err != nil {
		return nil, err
	}
	
	// Emit audit event for session revocation
	// TODO: Implement audit logging when ThemisLog is available
	// ThemisLog.LogEvent("SessionRevoked", map[string]string{"reason": req.Reason})
	
	return &RevocationResponse{
		Revoked:   true,
		Message:   "Session revoked successfully",
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}

// Helper methods for database operations

// storeSession stores session information in Dgraph
func (cs *ChronosSession) storeSession(_ context.Context, userID, token string, issuedAt, expiresAt time.Time, req *SessionRequest) error {
	// Hash the token for storage
	tokenHash := cs.hashToken(token)
	
	// Create session record in N-Quads format
	nquads := fmt.Sprintf(`
		_:session <dgraph.type> %q .
		_:session <userID> %q .
		_:session <tokenHash> %q .
		_:session <issuedAt> %q .
		_:session <expiresAt> %q .
		_:session <valid> "true"^^<xs:boolean> .
	`, cs.sessionRecordType, userID, tokenHash, issuedAt.Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	
	// Add optional fields if present
	if req.DeviceInfo != "" {
		nquads += fmt.Sprintf(`_:session <deviceInfo> %q .`, req.DeviceInfo)
	}
	if req.IPAddress != "" {
		nquads += fmt.Sprintf(`_:session <ipAddress> %q .`, req.IPAddress)
	}
	if req.UserAgent != "" {
		nquads += fmt.Sprintf(`_:session <userAgent> %q .`, req.UserAgent)
	}
	
	// Create mutation
	mu := dgraph.NewMutation().WithSetNquads(nquads)
	
	// Execute mutation
	_, err := dgraph.ExecuteMutations("dgraph", mu)
	return err
}

// hashToken creates a SHA-256 hash of the token for secure storage
func (cs *ChronosSession) hashToken(token string) string {
	hasher := sha256.New()
	hasher.Write([]byte(token))
	return base64.StdEncoding.EncodeToString(hasher.Sum(nil))
}

// isTokenValid checks if a token is still valid in the database
func (cs *ChronosSession) isTokenValid(_ context.Context, token string) (bool, error) {
	tokenHash := cs.hashToken(token)
	
	// DQL query to check if token exists and is valid
	query := fmt.Sprintf(`
		query {
			sessions(func: type(%s)) @filter(eq(tokenHash, "%s")) {
				uid
				valid
				expiresAt
			}
		}
	`, cs.sessionRecordType, tokenHash)
	
	// Execute query
	queryObj := dgraph.NewQuery(query)
	resp, err := dgraph.ExecuteQuery("dgraph", queryObj)
	if err != nil {
		return false, err
	}
	
	// Parse response
	type Result struct {
		Sessions []struct {
			UID       string `json:"uid"`
			Valid     bool   `json:"valid"`
			ExpiresAt string `json:"expiresAt"`
		} `json:"sessions"`
	}
	
	var result Result
	if resp.Json != "" {
		if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
			return false, err
		}
	}
	
	// Check if we found the session and it's valid
	if len(result.Sessions) == 0 {
		return false, nil
	}
	
	session := result.Sessions[0]
	
	// Check if the session is marked as valid
	if !session.Valid {
		return false, nil
	}
	
	// Check if the session has expired
	expiresAt, err := time.Parse(time.RFC3339, session.ExpiresAt)
	if err != nil {
		return false, err
	}
	
	if time.Now().After(expiresAt) {
		return false, nil
	}
	
	return true, nil
}

// updateLastUsed updates the lastUsed timestamp for a session
func (cs *ChronosSession) updateLastUsed(_ context.Context, token string) error {
	tokenHash := cs.hashToken(token)
	now := time.Now()
	
	// First, get the UID of the session
	query := fmt.Sprintf(`
		query {
			sessions(func: type(%s)) @filter(eq(tokenHash, "%s")) {
				uid
			}
		}
	`, cs.sessionRecordType, tokenHash)
	
	// Execute query
	queryObj := dgraph.NewQuery(query)
	resp, err := dgraph.ExecuteQuery("dgraph", queryObj)
	if err != nil {
		return err
	}
	
	// Parse response
	type Result struct {
		Sessions []struct {
			UID string `json:"uid"`
		} `json:"sessions"`
	}
	
	var result Result
	if resp.Json != "" {
		if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
			return err
		}
	}
	
	if len(result.Sessions) == 0 {
		return errors.New("session not found")
	}
	
	uid := result.Sessions[0].UID
	
	// Update lastUsed timestamp
	nquads := fmt.Sprintf(`
		<%s> <lastUsed> %q .
	`, uid, now.Format(time.RFC3339))
	
	// Create mutation
	mu := dgraph.NewMutation().WithSetNquads(nquads)
	
	// Execute mutation
	_, err = dgraph.ExecuteMutations("dgraph", mu)
	return err
}

// invalidateToken marks a token as invalid in the database
func (cs *ChronosSession) invalidateToken(_ context.Context, token string) error {
	tokenHash := cs.hashToken(token)
	
	// First, get the UID of the session
	query := fmt.Sprintf(`
		query {
			sessions(func: type(%s)) @filter(eq(tokenHash, "%s")) {
				uid
			}
		}
	`, cs.sessionRecordType, tokenHash)
	
	// Execute query
	queryObj := dgraph.NewQuery(query)
	resp, err := dgraph.ExecuteQuery("dgraph", queryObj)
	if err != nil {
		return err
	}
	
	// Parse response
	type Result struct {
		Sessions []struct {
			UID string `json:"uid"`
		} `json:"sessions"`
	}
	
	var result Result
	if resp.Json != "" {
		if err := json.Unmarshal([]byte(resp.Json), &result); err != nil {
			return err
		}
	}
	
	if len(result.Sessions) == 0 {
		return errors.New("session not found")
	}
	
	uid := result.Sessions[0].UID
	
	// Mark session as invalid
	nquads := fmt.Sprintf(`
		<%s> <valid> "false"^^<xs:boolean> .
	`, uid)
	
	// Create mutation
	mu := dgraph.NewMutation().WithSetNquads(nquads)
	
	// Execute mutation
	_, err = dgraph.ExecuteMutations("dgraph", mu)
	return err
}
