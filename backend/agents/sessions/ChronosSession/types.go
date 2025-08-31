package ChronosSession

import (
	"time"
)

// SessionRequest contains data for creating a new session
type SessionRequest struct {
	UserID          string                 `json:"userID"`
	AdditionalClaims map[string]interface{} `json:"additionalClaims,omitempty"`
	DeviceInfo      string                 `json:"deviceInfo,omitempty"`
	IPAddress       string                 `json:"ipAddress,omitempty"`
	UserAgent       string                 `json:"userAgent,omitempty"`
}

// SessionResponse contains the resulting session token and metadata
type SessionResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	IssuedAt  time.Time `json:"issuedAt"`
	UserID    string    `json:"userID"`
	Message   string    `json:"message,omitempty"`
}

// ValidationRequest for validating an existing session token
type ValidationRequest struct {
	Token string `json:"token"`
}

// ValidationResponse contains the results of token validation
type ValidationResponse struct {
	Valid     bool      `json:"valid"`
	UserID    string    `json:"userID,omitempty"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	Message   string    `json:"message,omitempty"`
}

// RefreshRequest for extending an existing session
type RefreshRequest struct {
	Token string `json:"token"`
}

// RevocationRequest for revoking a session
type RevocationRequest struct {
	Token  string `json:"token"`
	Reason string `json:"reason,omitempty"`
}

// RevocationResponse contains the result of session revocation
type RevocationResponse struct {
	Revoked   bool   `json:"revoked"`
	Message   string `json:"message,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// SESSION_TYPES are predefined session authentication method types
const (
	SESSION_TYPE_OTP       = "otp"
	SESSION_TYPE_WEBAUTHN  = "webauthn"
	SESSION_TYPE_PASSWORD  = "password"
	SESSION_TYPE_OAUTH     = "oauth"
	SESSION_TYPE_SSO       = "sso"
	SESSION_TYPE_TEMPORARY = "temporary"
)

// SessionRecord represents a session stored in the database
// Maps to AuthSession in Dgraph schema
type SessionRecord struct {
	UID        string    `json:"uid,omitempty"`
	User       string    `json:"user"`              // UID reference to user
	Method     string    `json:"method"`            // Authentication method
	TokenHash  string    `json:"tokenHash"`         // Internal use only - not in Dgraph schema
	CreatedAt  time.Time `json:"createdAt"`         // Maps to createdAt in Dgraph
	ExpiresAt  time.Time `json:"expiresAt"`         // Maps to expiresAt in Dgraph
	IPAddress  string    `json:"ipAddress,omitempty"`
	UserAgent  string    `json:"userAgent,omitempty"`
	DeviceID   string    `json:"deviceId,omitempty"` // Note: ID not Info to match schema
	Origin     string    `json:"origin,omitempty"`
	GeoLocation string   `json:"geoLocation,omitempty"` // UID reference to GeoLocation
	TLSCipher  string    `json:"tlsCipher,omitempty"`
	Valid      bool      `json:"valid"`             // Internal use only - not in Dgraph schema
	LastUsed   time.Time `json:"lastUsed,omitempty"` // Internal use only - not in Dgraph schema
}
