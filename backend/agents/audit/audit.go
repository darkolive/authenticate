package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// EntryParams defines the fields for writing an AuditEntry.
// Details can be provided either as a structured map (Details)
// or a pre-serialized JSON string (DetailsJSON).
// If both are provided, Details takes precedence.
// If RetentionYears is 0, defaults to 7 years.
// If Severity is empty, defaults to "INFO".
// If Source is empty, defaults to PerformedBy.
// Timestamp defaults to now if zero.
// TenantID is optional.
//
// Recommended usage: provide Details as a map for type safety.
// This helper handles JSON serialization and DQL escaping.
//
// NOTE: This helper writes using N-Quads via Modus Dgraph SDK.
// It mirrors the working approach used in CharonOTP and HecateRegister.

type EntryParams struct {
	Category     string
	Action       string
	ObjectType   string
	ObjectID     string
	PerformedBy  string
	Source       string
	Severity     string
	Timestamp    time.Time
	RetentionYears int
	Details      map[string]interface{}
	DetailsJSON  string
	TenantID     string
	IPAddress    string // optional raw IP; used only to derive ipHash predicate
	IPHash       string // optional precomputed ipHash; if set, takes precedence over IPAddress
	UserAgentRaw string // optional raw user agent; used to normalize and link to UserAgent node
}

// ensureUserAgentByRaw finds or creates a normalized UserAgent node by uaKey (sha256 of raw UA)
// Returns the UID of the UserAgent node.
func ensureUserAgentByRaw(rawUA string) (string, error) {
    key := sha256Hex(strings.TrimSpace(rawUA))
    // Query for existing UserAgent by uaKey
    q := fmt.Sprintf(`{ ua(func: eq(uaKey, %q), first: 1) { uid } }`, key)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    // If lookup succeeds, try to parse and return existing UID
    if err == nil && res.Json != "" {
        var parsed struct {
            UA []struct{ UID string `json:"uid"` } `json:"ua"`
        }
        if err := json.Unmarshal([]byte(res.Json), &parsed); err == nil {
            if len(parsed.UA) > 0 && parsed.UA[0].UID != "" {
                return parsed.UA[0].UID, nil
            }
        }
    }
    // Create new UserAgent node
    rawEsc := strings.ReplaceAll(rawUA, "\"", `\\\"`)
    nquads := fmt.Sprintf(`_:ua <dgraph.type> "UserAgent" .
_:ua <uaKey> %q .
_:ua <raw> %q .
`, key, rawEsc)
    mut := dgraph.NewMutation().WithSetNquads(nquads)
    result, err := dgraph.ExecuteMutations("dgraph", mut)
    if err != nil {
        return "", fmt.Errorf("userAgent create failed: %v", err)
    }
    if uid, ok := result.Uids["ua"]; ok && uid != "" {
        return uid, nil
    }
    return "", fmt.Errorf("userAgent created but UID not returned")
}

// computeIPHash derives a privacy-preserving, stable hash from a masked IP.
// IPv4: mask to /24 (zero last octet). IPv6: mask to /64 (zero last 8 bytes).
// Returns hex(SHA-256(maskedIPString)).
func computeIPHash(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		masked := make([]byte, len(v4))
		copy(masked, v4)
		masked[3] = 0 // /24
		return sha256Hex(net.IP(masked).String())
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	masked := make([]byte, len(v6))
	copy(masked, v6)
	for i := 8; i < 16; i++ { // /64
		masked[i] = 0
	}
	return sha256Hex(net.IP(masked).String())
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Log persists an AuditEntry to Dgraph and returns the generated audit ID.
func Log(p EntryParams) (string, error) {
	if p.Timestamp.IsZero() {
		p.Timestamp = time.Now().UTC()
	}
	if p.RetentionYears == 0 {
		p.RetentionYears = 7
	}
	if p.Severity == "" {
		p.Severity = "INFO"
	}
	if p.Source == "" {
		p.Source = p.PerformedBy
	}

	// Generate audit ID and retention date
	auditID := fmt.Sprintf("audit_%d", time.Now().UnixNano())
	retentionDate := p.Timestamp.AddDate(p.RetentionYears, 0, 0)

	// Prepare details JSON
	var detailsStr string
	if p.Details != nil {
		b, _ := json.Marshal(p.Details)
		detailsStr = string(b)
	} else if p.DetailsJSON != "" {
		detailsStr = p.DetailsJSON
	} else {
		detailsStr = "{}"
	}
	// Escape quotes for N-Quads
	detailsEscaped := strings.ReplaceAll(detailsStr, "\"", `\\"`)

	// Prepare typed timestamps
	ts := fmt.Sprintf("%q^^<xs:dateTime>", p.Timestamp.Format(time.RFC3339))
	rd := fmt.Sprintf("%q^^<xs:dateTime>", retentionDate.Format(time.RFC3339))

	// Optionally ensure a normalized UserAgent node and capture its UID
	var uaUID string
	if strings.TrimSpace(p.UserAgentRaw) != "" {
		var err error
		uaUID, err = ensureUserAgentByRaw(p.UserAgentRaw)
		if err != nil {
			// Do not fail the audit on UA normalization issues; continue without the edge
			uaUID = ""
		}
	}

	// Build N-Quads (use %q for proper quoting of string literals)
	nquads := fmt.Sprintf(`_:audit <id> %q .
_:audit <category> %q .
_:audit <action> %q .
_:audit <objectType> %q .
_:audit <objectId> %q .
_:audit <performedBy> %q .
_:audit <timestamp> %s .
_:audit <details> %q .
_:audit <severity> %q .
_:audit <source> %q .
_:audit <retentionDate> %s .
_:audit <dgraph.type> %q .`,
		auditID, p.Category, p.Action, p.ObjectType, p.ObjectID, p.PerformedBy,
		ts, detailsEscaped, p.Severity, p.Source, rd, "AuditEntry")

	// Optionally include tenantId if provided
	if p.TenantID != "" {
		nquads += fmt.Sprintf("\n_:audit <tenantId> %q .", p.TenantID)
	}

	// Optionally include ipHash if provided or derivable from IPAddress
	if p.IPHash != "" {
		nquads += fmt.Sprintf("\n_:audit <ipHash> %q .", p.IPHash)
	} else if p.IPAddress != "" {
		if hash := computeIPHash(p.IPAddress); hash != "" {
			nquads += fmt.Sprintf("\n_:audit <ipHash> %q .", hash)
		}
	}

	// Link to normalized UserAgent node if available
	if uaUID != "" {
		nquads += fmt.Sprintf("\n_:audit <userAgent> <%s> .", uaUID)
	}

	mut := dgraph.NewMutation().WithSetNquads(nquads)
	if _, err := dgraph.ExecuteMutations("dgraph", mut); err != nil {
		return "", fmt.Errorf("failed to write audit entry: %v", err)
	}
	return auditID, nil
}
