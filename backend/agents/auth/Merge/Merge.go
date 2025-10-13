//go:build !disable_merge
package Merge

import (
    "context"
    "encoding/json"
    "fmt"
    "strings"
    "time"

    audit "backend/agents/audit/ThemisLog"
    "github.com/hypermodeinc/modus/sdk/go/pkg/dgraph"
)

// ListMergeCandidates
// Input: userID (public DID)
// Output: pending merge candidates targeting this user

type ListMergeCandidatesRequest struct {
    UserID string `json:"userID"`
}

// --- Helpers for merge-to-oldest-user ---

type userMeta struct {
    UID       string
    DID       string
    CreatedAt time.Time
}

func getUserMeta(userUID string) (userMeta, error) {
    if strings.TrimSpace(userUID) == "" { return userMeta{}, fmt.Errorf("userUID required") }
    q := fmt.Sprintf(`{ u(func: uid(%s)) { uid did createdAt } }`, userUID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return userMeta{}, fmt.Errorf("user meta lookup failed: %v", err) }
    var parsed struct{ U []struct{ UID string `json:"uid"`; DID string `json:"did"`; CreatedAt string `json:"createdAt"` } `json:"u"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.U) == 0 { return userMeta{}, fmt.Errorf("user not found") }
    um := userMeta{ UID: strings.TrimSpace(parsed.U[0].UID), DID: strings.TrimSpace(parsed.U[0].DID) }
    if t := strings.TrimSpace(parsed.U[0].CreatedAt); t != "" { _ = um.CreatedAt.UnmarshalText([]byte(t)) }
    return um, nil
}

func getCandidateUserForMC(mcUID string) (string, error) {
    if strings.TrimSpace(mcUID) == "" { return "", fmt.Errorf("mergeCandidate UID required") }
    q := fmt.Sprintf(`{ mc(func: uid(%s)) { candidateUser { uid } } }`, mcUID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return "", fmt.Errorf("mc lookup failed: %v", err) }
    var parsed struct{ Mc []struct{ CandidateUser []struct{ UID string `json:"uid"` } `json:"candidateUser"` } `json:"mc"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.Mc) == 0 || len(parsed.Mc[0].CandidateUser) == 0 { return "", fmt.Errorf("candidate user missing") }
    return strings.TrimSpace(parsed.Mc[0].CandidateUser[0].UID), nil
}

func getClusterForUser(userUID string) (string, error) {
    if strings.TrimSpace(userUID) == "" { return "", fmt.Errorf("userUID required") }
    q := fmt.Sprintf(`{ c(func: type(IdentityCluster)) @filter(uid_in(hasUser, %s)) { uid } }`, userUID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return "", fmt.Errorf("cluster lookup failed: %v", err) }
    var parsed struct{ C []struct{ UID string `json:"uid"` } `json:"c"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.C) == 0 { return "", nil }
    return strings.TrimSpace(parsed.C[0].UID), nil
}

func ensureClusterForUser(userUID string) (string, error) {
    if cid, _ := getClusterForUser(userUID); cid != "" { return cid, nil }
    now := time.Now().UTC().Format(time.RFC3339)
    nq := fmt.Sprintf(`_:cl <dgraph.type> "IdentityCluster" .
_:cl <hasUser> <%s> .
_:cl <createdAt> "%s"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`, userUID, now)
    mu := dgraph.NewMutation().WithSetNquads(nq)
    resp, err := dgraph.ExecuteMutations("dgraph", mu)
    if err != nil { return "", fmt.Errorf("cluster create failed: %v", err) }
    cid := strings.TrimSpace(resp.Uids["cl"])
    if cid == "" { return "", fmt.Errorf("cluster UID not returned") }
    return cid, nil
}

func ensureUserInCluster(userUID, clusterUID string) error {
    if strings.TrimSpace(userUID) == "" || strings.TrimSpace(clusterUID) == "" { return nil }
    nq := fmt.Sprintf(`<%s> <hasUser> <%s> .
`, clusterUID, userUID)
    return setNquads(nq)
}

func detachUserFromOtherClusters(userUID, keepClusterUID string) error {
    if strings.TrimSpace(userUID) == "" || strings.TrimSpace(keepClusterUID) == "" { return nil }
    q := fmt.Sprintf(`{ c(func: type(IdentityCluster)) @filter(uid_in(hasUser, %s)) { uid } }`, userUID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return fmt.Errorf("cluster membership lookup failed: %v", err) }
    var parsed struct{ C []struct{ UID string `json:"uid"` } `json:"c"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    var del strings.Builder
    for _, c := range parsed.C {
        cu := strings.TrimSpace(c.UID)
        if cu == "" || cu == keepClusterUID { continue }
        del.WriteString(fmt.Sprintf(`<%s> <hasUser> <%s> .
`, cu, userUID))
    }
    if del.Len() == 0 { return nil }
    mu := dgraph.NewMutation().WithDelNquads(del.String())
    _, err = dgraph.ExecuteMutations("dgraph", mu)
    return err
}

func moveLegacyUserChannels(fromUserUID, toUserUID, toUserDID string) error {
    if strings.TrimSpace(fromUserUID) == "" || strings.TrimSpace(toUserUID) == "" || strings.TrimSpace(toUserDID) == "" { return nil }
    q := fmt.Sprintf(`{
      uc(func: type(UserChannels)) @filter(uid_in(user, %s)) {
        uid
        channelType
        channelHash
      }
    }`, fromUserUID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return fmt.Errorf("legacy channels lookup failed: %v", err) }
    var parsed struct{ Uc []struct{ UID string `json:"uid"`; ChannelType string `json:"channelType"`; ChannelHash string `json:"channelHash"` } `json:"uc"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.Uc) == 0 { return nil }
    var delB, setB strings.Builder
    for _, n := range parsed.Uc {
        u := strings.TrimSpace(n.UID)
        if u == "" { continue }
        delB.WriteString(fmt.Sprintf(`<%s> <user> <%s> .
`, u, fromUserUID))
        setB.WriteString(fmt.Sprintf(`<%s> <user> <%s> .
`, u, toUserUID))
        setB.WriteString(fmt.Sprintf(`<%s> <userId> %q .
`, u, toUserDID))
        // Recompute channelKey = did|type|hash using stored values
        legacyType := strings.TrimSpace(n.ChannelType)
        chHash := strings.TrimSpace(n.ChannelHash)
        setB.WriteString(fmt.Sprintf(`<%s> <channelKey> %q .
`, u, fmt.Sprintf("%s|%s|%s", toUserDID, legacyType, chHash)))
    }
    mu := dgraph.NewMutation()
    if delB.Len() > 0 { mu = mu.WithDelNquads(delB.String()) }
    if setB.Len() > 0 { mu = mu.WithSetNquads(setB.String()) }
    if delB.Len()+setB.Len() == 0 { return nil }
    _, err = dgraph.ExecuteMutations("dgraph", mu)
    return err
}

func copyRoles(fromUserUID, toUserUID string) error {
    if strings.TrimSpace(fromUserUID) == "" || strings.TrimSpace(toUserUID) == "" { return nil }
    q := fmt.Sprintf(`{ u(func: uid(%s)) { roles { uid } } }`, fromUserUID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return fmt.Errorf("roles lookup failed: %v", err) }
    var parsed struct{ U []struct{ Roles []struct{ UID string `json:"uid"` } `json:"roles"` } `json:"u"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.U) == 0 || len(parsed.U[0].Roles) == 0 { return nil }
    var setB strings.Builder
    for _, r := range parsed.U[0].Roles {
        ru := strings.TrimSpace(r.UID)
        if ru == "" { continue }
        setB.WriteString(fmt.Sprintf(`<%s> <roles> <%s> .
`, toUserUID, ru))
    }
    if setB.Len() == 0 { return nil }
    return setNquads(setB.String())
}

func removeAllRoles(userUID string) error {
    if strings.TrimSpace(userUID) == "" { return nil }
    q := fmt.Sprintf(`{ u(func: uid(%s)) { roles { uid } } }`, userUID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return fmt.Errorf("roles lookup failed: %v", err) }
    var parsed struct{ U []struct{ Roles []struct{ UID string `json:"uid"` } `json:"roles"` } `json:"u"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.U) == 0 || len(parsed.U[0].Roles) == 0 { return nil }
    var delB strings.Builder
    for _, r := range parsed.U[0].Roles {
        ru := strings.TrimSpace(r.UID)
        if ru == "" { continue }
        delB.WriteString(fmt.Sprintf(`<%s> <roles> <%s> .
`, userUID, ru))
    }
    if delB.Len() == 0 { return nil }
    mu := dgraph.NewMutation().WithDelNquads(delB.String())
    _, err = dgraph.ExecuteMutations("dgraph", mu)
    return err
}

func setNquads(nq string) error {
    if strings.TrimSpace(nq) == "" { return nil }
    mu := dgraph.NewMutation().WithSetNquads(nq)
    _, err := dgraph.ExecuteMutations("dgraph", mu)
    return err
}

// revokeAuthSessions marks all active sessions for a user as revoked and sets terminatedAt
func revokeAuthSessions(userUID string) error {
    if strings.TrimSpace(userUID) == "" { return nil }
    now := time.Now().UTC().Format(time.RFC3339)
    q := fmt.Sprintf(`{ s(func: type(AuthSession)) @filter(uid_in(user, %s) AND eq(revoked, false)) { uid } }`, userUID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return fmt.Errorf("sessions lookup failed: %v", err) }
    var parsed struct{ S []struct{ UID string `json:"uid"` } `json:"s"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.S) == 0 { return nil }
    var setB strings.Builder
    for _, s := range parsed.S {
        sid := strings.TrimSpace(s.UID)
        if sid == "" { continue }
        setB.WriteString(fmt.Sprintf(`<%s> <revoked> "true"^^<http://www.w3.org/2001/XMLSchema#boolean> .
<%s> <terminatedAt> "%s"^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`, sid, sid, now))
    }
    if setB.Len() == 0 { return nil }
    mu := dgraph.NewMutation().WithSetNquads(setB.String())
    _, err = dgraph.ExecuteMutations("dgraph", mu)
    return err
}

type MergeCandidateItem struct {
    UID            string    `json:"uid"`
    CandidateUser  string    `json:"candidateUser"`
    CandidateDID   string    `json:"candidateDID"`
    ChannelType    string    `json:"channelType"`
    ChannelHash    string    `json:"channelHash"`
    Signals        []string  `json:"signals"`
    Score          int       `json:"score"`
    Status         string    `json:"status"`
    CreatedAt      time.Time `json:"createdAt"`
}

type ListMergeCandidatesResponse struct {
    Items   []MergeCandidateItem `json:"items"`
    Message string               `json:"message,omitempty"`
}

func ListMergeCandidates(ctx context.Context, req ListMergeCandidatesRequest) (ListMergeCandidatesResponse, error) {
    did := strings.TrimSpace(req.UserID)
    if did == "" { return ListMergeCandidatesResponse{Items: nil, Message: "userID required"}, nil }
    userUID, err := getUserUIDByDID(did)
    if err != nil { return ListMergeCandidatesResponse{Items: nil, Message: "user not found"}, nil }

    q := fmt.Sprintf(`{
      mc(func: type(MergeCandidate)) @filter(uid_in(targetUser, %s) AND eq(status, "PENDING")) {
        uid
        score
        status
        channelType
        channelHash
        signals
        createdAt
        candidateUser { uid did }
      }
    }`, userUID)

    res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if qerr != nil { return ListMergeCandidatesResponse{Items: nil, Message: fmt.Sprintf("query failed: %v", qerr)}, nil }
    var parsed struct {
        Mc []struct {
            UID         string   `json:"uid"`
            Score       int      `json:"score"`
            Status      string   `json:"status"`
            ChannelType string   `json:"channelType"`
            ChannelHash string   `json:"channelHash"`
            Signals     []string `json:"signals"`
            CreatedAt   string   `json:"createdAt"`
            CandidateUser []struct { UID string `json:"uid"`; DID string `json:"did"` } `json:"candidateUser"`
        } `json:"mc"`
    }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    out := ListMergeCandidatesResponse{Items: []MergeCandidateItem{}}
    for _, m := range parsed.Mc {
        var t time.Time
        if m.CreatedAt != "" { _ = t.UnmarshalText([]byte(m.CreatedAt)) }
        item := MergeCandidateItem{
            UID: m.UID,
            ChannelType: m.ChannelType,
            ChannelHash: m.ChannelHash,
            Signals: m.Signals,
            Score: m.Score,
            Status: m.Status,
            CreatedAt: t,
        }
        if len(m.CandidateUser) > 0 {
            item.CandidateUser = m.CandidateUser[0].UID
            item.CandidateDID = m.CandidateUser[0].DID
        }
        out.Items = append(out.Items, item)
    }
    return out, nil
}

// ConfirmMergeCandidate marks a MergeCandidate as CONFIRMED or DISMISSED

type ConfirmMergeCandidateRequest struct {
    MergeCandidateUID string `json:"mergeCandidateUID"`
    Decision          string `json:"decision"` // "confirm" | "dismiss"
    UserID            string `json:"userID"`
}

type ConfirmMergeCandidateResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message,omitempty"`
}

func ConfirmMergeCandidate(ctx context.Context, req ConfirmMergeCandidateRequest) (ConfirmMergeCandidateResponse, error) {
    uid := strings.TrimSpace(req.MergeCandidateUID)
    if uid == "" { return ConfirmMergeCandidateResponse{Success: false, Message: "mergeCandidateUID required"}, nil }
    dec := strings.ToLower(strings.TrimSpace(req.Decision))
    status := ""
    switch dec {
    case "confirm": status = "CONFIRMED"
    case "dismiss": status = "DISMISSED"
    default: return ConfirmMergeCandidateResponse{Success: false, Message: "decision must be 'confirm' or 'dismiss'"}, nil
    }
    // Authorization: ensure requester matches targetUser of the candidate
    requesterUID, err := getUserUIDByDID(strings.TrimSpace(req.UserID))
    if err != nil {
        return ConfirmMergeCandidateResponse{Success: false, Message: "requester not found"}, nil
    }
    q := fmt.Sprintf(`{ mc(func: uid(%s)) { targetUser { uid } } }`, uid)
    res, qerr := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if qerr != nil { return ConfirmMergeCandidateResponse{Success: false, Message: "lookup failed"}, nil }
    var parsed struct{ Mc []struct{ TargetUser []struct{ UID string `json:"uid"` } `json:"targetUser"` } `json:"mc"` }
    if res.Json == "" { return ConfirmMergeCandidateResponse{Success: false, Message: "candidate not found"}, nil }
    _ = json.Unmarshal([]byte(res.Json), &parsed)
    if len(parsed.Mc) == 0 || len(parsed.Mc[0].TargetUser) == 0 || strings.TrimSpace(parsed.Mc[0].TargetUser[0].UID) != requesterUID {
        return ConfirmMergeCandidateResponse{Success: false, Message: "forbidden"}, nil
    }
    now := time.Now().UTC().Format(time.RFC3339)
    // When CONFIRMED, perform merge-to-oldest-user
    if status == "CONFIRMED" {
        // Load target/candidate meta
        tInfo, tErr := getUserMeta(requesterUID)
        if tErr != nil { return ConfirmMergeCandidateResponse{Success: false, Message: "failed to load target user"}, nil }
        // Find candidate UID via the MC node
        cUID, cLoadErr := getCandidateUserForMC(uid)
        if cLoadErr != nil || strings.TrimSpace(cUID) == "" {
            return ConfirmMergeCandidateResponse{Success: false, Message: "candidate user not found"}, nil
        }
        cInfo, cErr := getUserMeta(cUID)
        if cErr != nil { return ConfirmMergeCandidateResponse{Success: false, Message: "failed to load candidate user"}, nil }

        // Decide canonical: oldest createdAt; fallback to requester
        canonical := tInfo
        other := cInfo
        if !tInfo.CreatedAt.IsZero() && !cInfo.CreatedAt.IsZero() {
            if cInfo.CreatedAt.Before(tInfo.CreatedAt) {
                canonical = cInfo; other = tInfo
            }
        }

        // Ensure both users are in the canonical cluster
        canCluster, _ := getClusterForUser(canonical.UID)
        if canCluster == "" {
            // Create a new cluster under canonical if missing
            canCluster, _ = ensureClusterForUser(canonical.UID)
        }
        if canCluster != "" {
            _ = ensureUserInCluster(other.UID, canCluster)
            // Remove from any other clusters
            _ = detachUserFromOtherClusters(other.UID, canCluster)
        }

        // Reassign legacy UserChannels from other -> canonical
        _ = moveLegacyUserChannels(other.UID, canonical.UID, canonical.DID)

        // Copy roles from other to canonical; keep roles on other as-is or remove? We'll remove to avoid duplication
        _ = copyRoles(other.UID, canonical.UID)
        _ = removeAllRoles(other.UID)
        // Revoke all sessions for the merged (non-canonical) user
        _ = revokeAuthSessions(other.UID)

        // Mark other user as MERGED
        nqu := fmt.Sprintf(`<%s> <status> %q .
<%s> <updatedAt> %q^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`, other.UID, "MERGED", other.UID, now)
        _ = setNquads(nqu)
    }
    // Update MergeCandidate status and timestamp
    nq := fmt.Sprintf(`<%s> <status> %q .
<%s> <updatedAt> %q^^<http://www.w3.org/2001/XMLSchema#dateTime> .
`, uid, status, uid, now)
    mu := dgraph.NewMutation().WithSetNquads(nq)
    if _, err := dgraph.ExecuteMutations("dgraph", mu); err != nil {
        return ConfirmMergeCandidateResponse{Success: false, Message: fmt.Sprintf("update failed: %v", err)}, nil
    }

    // Audit
    _, _ = audit.Log(audit.EntryParams{
        Category:   "IDENTITY",
        Action:     "MERGE_CANDIDATE_" + status,
        ObjectType: "MergeCandidate",
        ObjectID:   uid,
        PerformedBy: req.UserID,
        Source:     "ConfirmMergeCandidate",
        Severity:   "INFO",
        Timestamp:  time.Now().UTC(),
    })

    return ConfirmMergeCandidateResponse{Success: true}, nil
}

// getUserUIDByDID local helper
func getUserUIDByDID(userID string) (string, error) {
    if strings.TrimSpace(userID) == "" { return "", fmt.Errorf("userID is required") }
    q := fmt.Sprintf(`{ u(func: eq(did, %q), first: 1) { uid } }`, userID)
    res, err := dgraph.ExecuteQuery("dgraph", dgraph.NewQuery(q))
    if err != nil { return "", fmt.Errorf("user lookup failed: %v", err) }
    var parsed struct{ U []struct{ UID string `json:"uid"` } `json:"u"` }
    if res.Json != "" { _ = json.Unmarshal([]byte(res.Json), &parsed) }
    if len(parsed.U) == 0 || strings.TrimSpace(parsed.U[0].UID) == "" { return "", fmt.Errorf("user not found") }
    return parsed.U[0].UID, nil
}
