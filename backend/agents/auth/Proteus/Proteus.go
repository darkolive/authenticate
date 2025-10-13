//go:build !disable_proteus
package Proteus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	audit "backend/agents/audit/ThemisLog"
	mfa "backend/agents/auth/CharonOTP"
	aegis "backend/services/aegis"

	"github.com/hypermodeinc/modus/sdk/go/pkg/console"
	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
	phonenumbers "github.com/nyaruka/phonenumbers"
)

// LinkChannelStartRequest starts a channel linking flow by issuing a challenge (OTP/OAuth/etc)
// For phase 1 we support email and sms/whatsapp via OTP
// UserID must be the application's DID for the signed-in user
// ChannelType is one of: email | sms | whatsapp
// Value is the user-provided address/number
//
// Example (SMS): {"userID":"did:app:123","channelType":"sms","value":"07943..."}

func reassignChannelOwner(channelUID, oldClusterUID, newClusterUID string) error {
	if strings.TrimSpace(channelUID) == "" || strings.TrimSpace(newClusterUID) == "" {
		return fmt.Errorf("channelUID and newClusterUID are required")
	}
	// Build delete and set N-Quads
	del := new(strings.Builder)
	if strings.TrimSpace(oldClusterUID) != "" {
		del.WriteString(fmt.Sprintf("<%s> <ownedBy> <%s> .\n", channelUID, oldClusterUID))
		del.WriteString(fmt.Sprintf("<%s> <hasChannel> <%s> .\n", oldClusterUID, channelUID))
	}
	set := fmt.Sprintf("<%s> <ownedBy> <%s> .\n<%s> <hasChannel> <%s> .\n", channelUID, newClusterUID, newClusterUID, channelUID)
	mu := dgraph.NewMutation().WithSetNquads(set)
	if del.Len() > 0 { mu = mu.WithDelNquads(del.String()) }
	_, err := dgraph.ExecuteMutations("dgraph", mu)
	return err
}

// ----- Linked channels query API -----

type GetLinkedChannelsRequest struct {
	UserID string `json:"userID"`
}

type LinkedChannel struct {
	UID             string    `json:"uid"`
	ChannelType     string    `json:"channelType"`
	Verified        bool      `json:"verified"`
	NormalizedValue string    `json:"normalizedValue"`
	Provider        string    `json:"provider,omitempty"`
	Subject         string    `json:"subject,omitempty"`
	LastVerifiedAt  time.Time `json:"lastVerifiedAt,omitempty"`
}

type GetLinkedChannelsResponse struct {
	ClusterUID string          `json:"clusterUID,omitempty"`
	Channels   []LinkedChannel `json:"channels"`
	Message    string          `json:"message,omitempty"`
}

// GetLinkedChannels returns the user's cluster UID and any linked channels
func GetLinkedChannels(ctx context.Context, req GetLinkedChannelsRequest) (GetLinkedChannelsResponse, error) {
	userUID, err := getUserUIDByDID(strings.TrimSpace(req.UserID))
	if err != nil {
		return GetLinkedChannelsResponse{Channels: nil, Message: "user not found"}, nil
	}
	q := fmt.Sprintf(`{
	  c(func: type(IdentityCluster)) @filter(uid_in(hasUser, %s)) {
		uid
		hasChannel {
		  uid
		  channelType
		  verified
		  value_enc
		  provider
		  subject
		  lastVerifiedAt
		}
	  }
	}`, userUID)
	res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
	if qerr != nil {
		return GetLinkedChannelsResponse{Channels: nil, Message: fmt.Sprintf("query failed: %v", qerr)}, nil
	}
	var parsed struct {
		C []struct {
			UID        string `json:"uid"`
			HasChannel []struct {
				UID             string    `json:"uid"`
				ChannelType     string    `json:"channelType"`
				Verified        bool      `json:"verified"`
				ValueEnc        string    `json:"value_enc"`
				Provider        string    `json:"provider"`
				Subject         string    `json:"subject"`
				LastVerifiedAt  time.Time `json:"lastVerifiedAt"`
			} `json:"hasChannel"`
		} `json:"c"`
	}
	if res.Json != "" {
		_ = json.Unmarshal([]byte(res.Json), &parsed)
	}
	out := GetLinkedChannelsResponse{Channels: []LinkedChannel{}}
	if len(parsed.C) == 0 {
		return out, nil
	}
	out.ClusterUID = strings.TrimSpace(parsed.C[0].UID)
	for _, ch := range parsed.C[0].HasChannel {
		var plain string
		if strings.TrimSpace(ch.ValueEnc) != "" {
			if pt, derr := aegis.Decrypt("pii-contact", strings.TrimSpace(ch.ValueEnc)); derr == nil {
				plain = string(pt)
			}
		}
		out.Channels = append(out.Channels, LinkedChannel{
			UID:             ch.UID,
			ChannelType:     ch.ChannelType,
			Verified:        ch.Verified,
			NormalizedValue: plain, // subject can view unencrypted
			Provider:        ch.Provider,
			Subject:         ch.Subject,
			LastVerifiedAt:  ch.LastVerifiedAt,
		})
	}
	return out, nil
}

func getChannelOwner(channelUID string) (string, error) {
	if strings.TrimSpace(channelUID) == "" { return "", fmt.Errorf("channelUID is required") }
	q := fmt.Sprintf(`{ ch(func: uid(%s)) { ownedBy { uid } } }`, channelUID)
	res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
	if err != nil { return "", fmt.Errorf("owner lookup failed: %v", err) }
	var parsed struct{ Ch []struct{ OwnedBy []struct{ UID string `json:"uid"` } `json:"ownedBy"` } `json:"ch"` }
	if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
	if len(parsed.Ch) == 0 || len(parsed.Ch[0].OwnedBy) == 0 { return "", nil }
	return strings.TrimSpace(parsed.Ch[0].OwnedBy[0].UID), nil
}
// Example (Email): {"userID":"did:app:123","channelType":"email","value":"user@example.com"}
type LinkChannelStartRequest struct {
	UserID      string `json:"userID"`
	ChannelType string `json:"channelType"`
	Value       string `json:"value"`
}

type LinkChannelStartResponse struct {
	Success       bool      `json:"success"`
	Message       string    `json:"message,omitempty"`
	LinkID        string    `json:"linkId,omitempty"`        // OTP ID if applicable
	ChallengeType string    `json:"challengeType,omitempty"` // "otp" for email/sms/whatsapp
	Destination   string    `json:"destination,omitempty"`   // masked value for UI
	ExpiresAt     string    `json:"expiresAt,omitempty"`
}

// LinkChannelConfirmRequest completes the linking by validating the challenge
// For OTP channels provide otpCode; OAuth/device flows would provide alternative tokens later
// Provider/Subject are optional for future OAuth flows
type LinkChannelConfirmRequest struct {
	UserID      string `json:"userID"`
	ChannelType string `json:"channelType"`
	Value       string `json:"value"`
	OTPCode     string `json:"otpCode,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Subject     string `json:"subject,omitempty"`
}

type LinkChannelConfirmResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message,omitempty"`
	ChannelUID string `json:"channelUID,omitempty"`
	ClusterUID string `json:"clusterUID,omitempty"`
}

// LinkChannelStart sends an OTP when channelType is email/sms/whatsapp and returns a link token
func LinkChannelStart(ctx context.Context, req LinkChannelStartRequest) (LinkChannelStartResponse, error) {
	// Basic validation
	ctype := strings.ToLower(strings.TrimSpace(req.ChannelType))
	val := strings.TrimSpace(req.Value)
	if strings.TrimSpace(req.UserID) == "" || ctype == "" || val == "" {
		return LinkChannelStartResponse{Success: false, Message: "userID, channelType and value are required"}, nil
	}
	if ctype != "email" && ctype != "sms" && ctype != "whatsapp" {
		return LinkChannelStartResponse{Success: false, Message: fmt.Sprintf("unsupported channelType: %s", req.ChannelType)}, nil
	}

	// Issue OTP via existing CharonOTP agent
	otpResp, err := mfa.SendOTP(ctx, mfa.OTPRequest{Channel: ctype, Recipient: val})
	if err != nil {
		console.Error(fmt.Sprintf("Proteus LinkChannelStart OTP send failed: %v", err))
		return LinkChannelStartResponse{Success: false, Message: fmt.Sprintf("failed to send OTP: %v", err)}, nil
	}

	masked := maskDestination(ctype, val)
	return LinkChannelStartResponse{
		Success:       otpResp.Sent,
		Message:       otpResp.Message,
		LinkID:        otpResp.OTPID,
		ChallengeType: "otp",
		Destination:   masked,
		ExpiresAt:     otpResp.ExpiresAt.Format(time.RFC3339),
	}, nil
}

// LinkChannelConfirm verifies the challenge and attaches the channel to the user's IdentityCluster
func LinkChannelConfirm(ctx context.Context, req LinkChannelConfirmRequest) (LinkChannelConfirmResponse, error) {
	ctype := strings.ToLower(strings.TrimSpace(req.ChannelType))
	val := strings.TrimSpace(req.Value)
	userID := strings.TrimSpace(req.UserID)
	if userID == "" || ctype == "" || val == "" {
		return LinkChannelConfirmResponse{Success: false, Message: "userID, channelType and value are required"}, nil
	}

	// Phase 1: OTP verification for email/sms/whatsapp
	if ctype == "email" || ctype == "sms" || ctype == "whatsapp" {
		if strings.TrimSpace(req.OTPCode) == "" {
			return LinkChannelConfirmResponse{Success: false, Message: "otpCode is required for this channel"}, nil
		}
		vr, err := mfa.VerifyOTP(mfa.VerifyOTPRequest{OTPCode: req.OTPCode, Recipient: val})
		if err != nil || !vr.Verified {
			if err != nil {
				console.Error(fmt.Sprintf("Proteus VerifyOTP error: %v", err))
			}
			return LinkChannelConfirmResponse{Success: false, Message: "invalid or expired OTP"}, nil
		}
	}

	// Resolve User UID
	userUID, err := getUserUIDByDID(userID)
	if err != nil {
		return LinkChannelConfirmResponse{Success: false, Message: "user not found"}, nil
	}

	// Ensure IdentityCluster for the user
	clusterUID, err := getOrCreateClusterForUser(userUID)
	if err != nil {
		return LinkChannelConfirmResponse{Success: false, Message: fmt.Sprintf("cluster error: %v", err)}, nil
	}

	// Create or find Channel
	norm := normalizeForHash(ctype, val)
	hash := hashString(fmt.Sprintf("%s:%s", ctype, norm))
	channelUID, err := getOrCreateChannel(ctype, norm, hash, strings.TrimSpace(req.Provider), strings.TrimSpace(req.Subject))
	if err != nil {
		return LinkChannelConfirmResponse{Success: false, Message: fmt.Sprintf("channel error: %v", err)}, nil
	}

	// Conflict handling: if already owned by a different cluster, reassign ownership to this user's cluster
	if ownerUID, ownErr := getChannelOwner(channelUID); ownErr == nil && ownerUID != "" && ownerUID != clusterUID {
		if err := reassignChannelOwner(channelUID, ownerUID, clusterUID); err != nil {
			return LinkChannelConfirmResponse{Success: false, Message: fmt.Sprintf("claim failed: %v", err)}, nil
		}
		// Audit unlink from previous cluster
		_, _ = audit.Log(audit.EntryParams{
			Category:   "IDENTITY",
			Action:     "CHANNEL_UNLINKED",
			ObjectType: "Channel",
			ObjectID:   channelUID,
			PerformedBy: "Proteus",
			Source:     "LinkChannelConfirm",
			Severity:   "INFO",
			Timestamp:  time.Now().UTC(),
			Details: map[string]any{
				"previousClusterUID": ownerUID,
				"newClusterUID":     clusterUID,
				"reason":            "claimed_via_verified_otp",
			},
		})
	} else {
		// No conflict (or already same cluster) — attach normally
		if err := attachChannelToCluster(channelUID, clusterUID); err != nil {
			return LinkChannelConfirmResponse{Success: false, Message: fmt.Sprintf("link error: %v", err)}, nil
		}
	}
	if err := markChannelVerified(channelUID); err != nil {
		console.Warn(fmt.Sprintf("markChannelVerified warning: %v", err))
	}

	// Mirror into legacy UserChannels so CerberusMFA can resolve existing users on OTP sign-in
	// Map Proteus types -> legacy types: email -> email, sms/whatsapp -> phone
	legacyType := "email"
	if ctype != "email" {
		legacyType = "phone"
	}
	if merr := ensureLegacyUserChannel(legacyType, norm, userUID, userID); merr != nil {
		console.Warn(fmt.Sprintf("mirror UserChannels failed: %v", merr))
	}

	// Audit
	_, _ = audit.Log(audit.EntryParams{
		Category:   "IDENTITY",
		Action:     "CHANNEL_LINKED",
		ObjectType: "Channel",
		ObjectID:   channelUID,
		PerformedBy: "Proteus",
		Source:     "LinkChannelConfirm",
		Severity:   "INFO",
		Timestamp:  time.Now().UTC(),
		Details: map[string]any{
			"userID":      userID,
			"userUID":     userUID,
			"clusterUID":  clusterUID,
			"channelType": ctype,
		},
	})

	return LinkChannelConfirmResponse{Success: true, ChannelUID: channelUID, ClusterUID: clusterUID}, nil
}

// --- Helpers ---

func maskDestination(channelType, value string) string {
	v := strings.TrimSpace(value)
	switch strings.ToLower(channelType) {
	case "email":
		parts := strings.Split(v, "@")
		if len(parts) != 2 {
			return "***"
		}
		local, domain := parts[0], parts[1]
		if len(local) <= 2 {
			return "***@" + domain
		}
		return fmt.Sprintf("%c***%c@%s", local[0], local[len(local)-1], domain)
	case "sms", "whatsapp":
		// show last 2 digits of E.164-normalized value when possible
		nv := normalizePhoneE164(v)
		if len(nv) < 2 {
			return "***"
		}
		return fmt.Sprintf("***%s", nv[len(nv)-2:])
	default:
		return "***"
	}
}

func normalizeForHash(channelType, value string) string {
	v := strings.TrimSpace(value)
	if strings.ToLower(channelType) == "email" {
		return strings.ToLower(v)
	}
	// For phone-like channels, use E.164 normalization for consistent hashing
	return normalizePhoneE164(v)
}

func normalizePhoneE164(input string) string {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return ""
	}
	region := strings.TrimSpace(os.Getenv("TWILIO_DEFAULT_COUNTRY_CODE"))
	if region == "" {
		region = "US"
	}
	if num, err := phonenumbers.Parse(raw, region); err == nil && phonenumbers.IsValidNumber(num) {
		return phonenumbers.Format(num, phonenumbers.E164)
	}
	// Fallback: digits only, preserve leading '+'
	var b strings.Builder
	for i, r := range raw {
		if r == '+' && i == 0 {
			b.WriteRune(r)
			continue
		}
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hashString(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

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
	if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
	if len(parsed.U) == 0 || strings.TrimSpace(parsed.U[0].UID) == "" {
		return "", fmt.Errorf("user not found")
	}
	return parsed.U[0].UID, nil
}

func getOrCreateClusterForUser(userUID string) (string, error) {
	// Find existing cluster via forward edge (no reverse required)
	q := fmt.Sprintf(`{
	  c(func: type(IdentityCluster)) @filter(uid_in(hasUser, %s)) {
		uid
	  }
	}`, userUID)
	res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
	if err != nil {
		return "", fmt.Errorf("cluster lookup failed: %v", err)
	}
	var parsed struct{ C []struct{ UID string `json:"uid"` } `json:"c"` }
	if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
	if len(parsed.C) > 0 && strings.TrimSpace(parsed.C[0].UID) != "" {
		return parsed.C[0].UID, nil
	}
	// Create cluster
	now := time.Now().UTC().Format(time.RFC3339)
	nq := fmt.Sprintf(`_:cluster <dgraph.type> "IdentityCluster" .
_:cluster <hasUser> <%s> .
_:cluster <createdAt> "%s"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`, userUID, now)
	mu := dgraph.NewMutation().WithSetNquads(nq)
	resp, err := dgraph.ExecuteMutations("dgraph", mu)
	if err != nil {
		return "", fmt.Errorf("cluster create failed: %v", err)
	}
	cid := resp.Uids["cluster"]
	if strings.TrimSpace(cid) == "" { return "", fmt.Errorf("cluster UID not returned") }
	return cid, nil
}

func getOrCreateChannel(ctype, normalizedValue, channelHash, provider, subject string) (string, error) {
	// Check by hash
	q := fmt.Sprintf(`{ ch(func: eq(channelHash, %q), first: 1) { uid } }`, channelHash)
	res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
	if err != nil {
		return "", fmt.Errorf("channel lookup failed: %v", err)
	}
	var parsed struct{ Ch []struct{ UID string `json:"uid"` } `json:"ch"` }
	if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
	if len(parsed.Ch) > 0 && parsed.Ch[0].UID != "" {
		return parsed.Ch[0].UID, nil
	}
	// Create new channel
	nq := new(strings.Builder)
	nq.WriteString("_:ch <dgraph.type> \"Channel\".\n")
	nq.WriteString(fmt.Sprintf("_:ch <channelType> %q.\n", ctype))
	nq.WriteString(fmt.Sprintf("_:ch <channelHash> %q.\n", channelHash))
	// Store encrypted value and blind index instead of plaintext
	if ct, err := aegis.Encrypt("pii-contact", []byte(normalizedValue)); err == nil {
		nq.WriteString(fmt.Sprintf("_:ch <value_enc> %q.\n", ct))
	}
	if bi, err := aegis.HMAC("pii-contact-hmac", []byte(normalizedValue)); err == nil {
		nq.WriteString(fmt.Sprintf("_:ch <value_bi> %q.\n", bi))
	}
	if provider != "" { nq.WriteString(fmt.Sprintf("_:ch <provider> %q.\n", provider)) }
	if subject != "" { nq.WriteString(fmt.Sprintf("_:ch <subject> %q.\n", subject)) }
	nq.WriteString("_:ch <verified> \"false\"^^<http://www.w3.org/2001/XMLSchema#boolean>.\n")
	mu := dgraph.NewMutation().WithSetNquads(nq.String())
	resp, err := dgraph.ExecuteMutations("dgraph", mu)
	if err != nil {
		return "", fmt.Errorf("channel create failed: %v", err)
	}
	cid := resp.Uids["ch"]
	if strings.TrimSpace(cid) == "" { return "", fmt.Errorf("channel UID not returned") }
	return cid, nil
}

func attachChannelToCluster(channelUID, clusterUID string) error {
    nq := fmt.Sprintf(`<%s> <ownedBy> <%s> .
<%s> <hasChannel> <%s> .
`, channelUID, clusterUID, clusterUID, channelUID)
    mu := dgraph.NewMutation().WithSetNquads(nq)
    _, err := dgraph.ExecuteMutations("dgraph", mu)
    return err
}

func markChannelVerified(channelUID string) error {
    now := time.Now().UTC().Format(time.RFC3339)
    nq := fmt.Sprintf(`<%s> <verified> "true"^^<http://www.w3.org/2001/XMLSchema#boolean> .
<%s> <lastVerifiedAt> "%s"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`, channelUID, channelUID, now)
    mu := dgraph.NewMutation().WithSetNquads(nq)
    _, err := dgraph.ExecuteMutations("dgraph", mu)
    return err
}

// ensureLegacyUserChannel upserts a corresponding UserChannels record for compatibility with CerberusMFA lookups
// legacyType must be one of: "email" | "phone"
// normalized is the normalized channel value (lowercased email; trimmed phone)
// userUID is the Dgraph UID of the User; did is the public DID string
func ensureLegacyUserChannel(legacyType, normalized, userUID, did string) error {
    lt := strings.ToLower(strings.TrimSpace(legacyType))
    if lt != "email" && lt != "phone" {
        return fmt.Errorf("unsupported legacyType: %s", legacyType)
    }
    if strings.TrimSpace(normalized) == "" || strings.TrimSpace(userUID) == "" || strings.TrimSpace(did) == "" {
        return fmt.Errorf("normalized, userUID and did are required")
    }
    chHash := hashString(normalized)
    key := fmt.Sprintf("%s|%s|%s", did, lt, chHash)
    unique := fmt.Sprintf("%s|%s", lt, chHash)

    // 1) Reassign any existing records by channelUnique to this user (avoids duplicates and misrouting)
    qUnique := fmt.Sprintf(`{ uc(func: eq(channelUnique, %q)) { uid user { uid } } }`, unique)
    resU, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(qUnique))
    if err != nil { return fmt.Errorf("unique lookup failed: %v", err) }
    var parsedU struct {
        Uc []struct {
            UID  string `json:"uid"`
            User []struct{ UID string `json:"uid"` } `json:"user"`
        } `json:"uc"`
    }
    if resU.Json != "" { _ = json.Unmarshal([]byte(resU.Json), &parsedU) }
    now := time.Now().UTC().Format(time.RFC3339)
    if len(parsedU.Uc) > 0 {
        // Update all matches to point to the correct user and refresh timestamps
        var delB strings.Builder
        var setB strings.Builder
        for _, n := range parsedU.Uc {
            ucUID := strings.TrimSpace(n.UID)
            if ucUID == "" { continue }
            // remove old user edges if they point elsewhere
            for _, ou := range n.User {
                ouid := strings.TrimSpace(ou.UID)
                if ouid != "" && ouid != userUID {
                    delB.WriteString(fmt.Sprintf("<%s> <user> <%s> .\n", ucUID, ouid))
                }
            }
            // set to current user and bump fields
            setB.WriteString(fmt.Sprintf("<%s> <user> <%s> .\n", ucUID, userUID))
            setB.WriteString(fmt.Sprintf("<%s> <userId> %q .\n", ucUID, did))
            setB.WriteString(fmt.Sprintf("<%s> <verified> \"true\"^^<http://www.w3.org/2001/XMLSchema#boolean> .\n", ucUID))
            setB.WriteString(fmt.Sprintf("<%s> <lastUsedAt> \"%s\"^^<http://www.w3.org/2001/XMLSchema#dateTime> .\n", ucUID, now))
        }
        mu := dgraph.NewMutation()
        if delB.Len() > 0 { mu = mu.WithDelNquads(delB.String()) }
        if setB.Len() > 0 { mu = mu.WithSetNquads(setB.String()) }
        if delB.Len()+setB.Len() > 0 {
            if _, err := dgraph.ExecuteMutations("dgraph", mu); err != nil {
                return fmt.Errorf("unique reassign failed: %v", err)
            }
        }
        return nil
    }

    // 2) Look for existing UserChannels by channelKey for this user
    qKey := fmt.Sprintf(`{ uc(func: eq(channelKey, %q), first: 1) { uid } }`, key)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(qKey))
    if err != nil { return fmt.Errorf("lookup failed: %v", err) }
    var parsed struct{ Uc []struct{ UID string `json:"uid"` } `json:"uc"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.Uc) > 0 && strings.TrimSpace(parsed.Uc[0].UID) != "" {
        uid := strings.TrimSpace(parsed.Uc[0].UID)
        nq := fmt.Sprintf(`<%s> <verified> "true"^^<http://www.w3.org/2001/XMLSchema#boolean> .
<%s> <lastUsedAt> "%s"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`, uid, uid, now)
        mu := dgraph.NewMutation().WithSetNquads(nq)
        if _, err := dgraph.ExecuteMutations("dgraph", mu); err != nil {
            return fmt.Errorf("update failed: %v", err)
        }
        return nil
    }

    // 3) Create new UserChannels node
    nq := fmt.Sprintf(`_:uc <dgraph.type> "UserChannels" .
_:uc <user> <%s> .
_:uc <userId> %q .
_:uc <channelType> %q .
_:uc <channelHash> %q .
_:uc <channelKey> %q .
_:uc <channelUnique> %q .
_:uc <verified> "true"^^<http://www.w3.org/2001/XMLSchema#boolean> .
_:uc <primary> "false"^^<http://www.w3.org/2001/XMLSchema#boolean> .
_:uc <createdAt> "%s"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
_:uc <lastUsedAt> "%s"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`, userUID, did, lt, chHash, key, unique, now, now)
    // Attach encrypted value and blind index
    if ct, err := aegis.Encrypt("pii-contact", []byte(normalized)); err == nil {
        nq += fmt.Sprintf("\n_:uc <value_enc> %q .", ct)
    }
    if bi, err := aegis.HMAC("pii-contact-hmac", []byte(normalized)); err == nil {
        nq += fmt.Sprintf("\n_:uc <value_bi> %q .", bi)
    }
    mu := dgraph.NewMutation().WithSetNquads(nq)
    if _, err := dgraph.ExecuteMutations("dgraph", mu); err != nil {
        return fmt.Errorf("create failed: %v", err)
    }
    return nil
}
