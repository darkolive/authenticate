package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/hypermodeinc/modus/sdk/go/pkg/http"
)

// baseURL returns the Vault API base URL, defaulting to local dev if not set.
func baseURL() string {
	b := strings.TrimSpace(os.Getenv("VAULT_ADDR"))
	if b == "" {
		b = "http://127.0.0.1:8200/v1/"
	}
	return b
}

// Encrypt uses Vault Transit encrypt on the given key. Returns ciphertext like "vault:v1:...".
func Encrypt(key string, plaintext []byte) (string, error) {
	url := fmt.Sprintf("%stransit/encrypt/%s", baseURL(), key)
	body := map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}
	payload, _ := json.Marshal(body)
	req := http.NewRequest(url, &http.RequestOptions{Method: "POST", Body: payload})
	resp, err := http.Fetch(req)
	if err != nil {
		return "", fmt.Errorf("vault encrypt failed: %w", err)
	}
	if !resp.Ok() {
		return "", fmt.Errorf("vault encrypt error: %d %s - %s", resp.Status, resp.StatusText, resp.Text())
	}
	var out struct{ Data struct{ Ciphertext string `json:"ciphertext"` } `json:"data"` }
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return "", fmt.Errorf("vault encrypt parse error: %w", err)
	}
	if strings.TrimSpace(out.Data.Ciphertext) == "" {
		return "", fmt.Errorf("vault encrypt: empty ciphertext")
	}
	return out.Data.Ciphertext, nil
}

// Decrypt uses Vault Transit decrypt on the given key. Returns raw plaintext bytes.
func Decrypt(key string, ciphertext string) ([]byte, error) {
	url := fmt.Sprintf("%stransit/decrypt/%s", baseURL(), key)
	body := map[string]any{
		"ciphertext": ciphertext,
	}
	payload, _ := json.Marshal(body)
	req := http.NewRequest(url, &http.RequestOptions{Method: "POST", Body: payload})
	resp, err := http.Fetch(req)
	if err != nil {
		return nil, fmt.Errorf("vault decrypt failed: %w", err)
	}
	if !resp.Ok() {
		return nil, fmt.Errorf("vault decrypt error: %d %s - %s", resp.Status, resp.StatusText, resp.Text())
	}
	var out struct{ Data struct{ Plaintext string `json:"plaintext"` } `json:"data"` }
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("vault decrypt parse error: %w", err)
	}
	if strings.TrimSpace(out.Data.Plaintext) == "" {
		return nil, fmt.Errorf("vault decrypt: empty plaintext")
	}
	pt, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault decrypt base64 decode error: %w", err)
	}
	return pt, nil
}

// HMAC computes a deterministic HMAC via Vault Transit. Returns the Vault HMAC string (e.g., "vault:v1:...hex")
func HMAC(key string, input []byte) (string, error) {
	url := fmt.Sprintf("%stransit/hmac/%s", baseURL(), key)
	body := map[string]any{
		"input": base64.StdEncoding.EncodeToString(input),
		"algorithm": "sha2-256",
	}
	payload, _ := json.Marshal(body)
	req := http.NewRequest(url, &http.RequestOptions{Method: "POST", Body: payload})
	resp, err := http.Fetch(req)
	if err != nil {
		return "", fmt.Errorf("vault hmac failed: %w", err)
	}
	if !resp.Ok() {
		return "", fmt.Errorf("vault hmac error: %d %s - %s", resp.Status, resp.StatusText, resp.Text())
	}
	var out struct{ Data struct{ HMAC string `json:"hmac"` } `json:"data"` }
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return "", fmt.Errorf("vault hmac parse error: %w", err)
	}
	if strings.TrimSpace(out.Data.HMAC) == "" {
		return "", fmt.Errorf("vault hmac: empty output")
	}
	return out.Data.HMAC, nil
}
