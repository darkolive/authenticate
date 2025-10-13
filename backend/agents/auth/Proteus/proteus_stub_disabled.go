//go:build disable_proteus

package Proteus

import (
    "context"
    "time"
)

// Stub types and resolvers for when the Proteus agent is disabled at build time.
// This allows the project to compile with `-tags disable_proteus` while keeping
// the main GraphQL resolvers intact.

// ----- Linked channels query API (stubs) -----
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

func GetLinkedChannels(_ context.Context, _ GetLinkedChannelsRequest) (GetLinkedChannelsResponse, error) {
    return GetLinkedChannelsResponse{Channels: []LinkedChannel{}, Message: "Proteus disabled"}, nil
}

// ----- Link channel flow (stubs) -----

type LinkChannelStartRequest struct {
    UserID      string `json:"userID"`
    ChannelType string `json:"channelType"`
    Value       string `json:"value"`
}

type LinkChannelStartResponse struct {
    Success       bool   `json:"success"`
    Message       string `json:"message,omitempty"`
    LinkID        string `json:"linkId,omitempty"`
    ChallengeType string `json:"challengeType,omitempty"`
    Destination   string `json:"destination,omitempty"`
    ExpiresAt     string `json:"expiresAt,omitempty"`
}

func LinkChannelStart(_ context.Context, _ LinkChannelStartRequest) (LinkChannelStartResponse, error) {
    return LinkChannelStartResponse{Success: false, Message: "Proteus disabled"}, nil
}

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

func LinkChannelConfirm(_ context.Context, _ LinkChannelConfirmRequest) (LinkChannelConfirmResponse, error) {
    return LinkChannelConfirmResponse{Success: false, Message: "Proteus disabled"}, nil
}
