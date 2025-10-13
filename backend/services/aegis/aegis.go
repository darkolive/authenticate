package aegis

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// masterKeyBytes returns a 32-byte key derived from AEGIS_MASTER_KEY.
// If unset, derives from a constant dev seed. This is for local/dev only.
func masterKeyBytes() []byte {
	seed := strings.TrimSpace(os.Getenv("AEGIS_MASTER_KEY"))
	if seed == "" {
		seed = "dev-insecure-aegis-master-key"
	}
	h := sha256.Sum256([]byte(seed))
	return h[:]
}

// kdf derives a 32-byte subkey for a given namespace and purpose ("enc" or "hmac").
func kdf(namespace, purpose string) []byte {
	m := masterKeyBytes()
	h := hmac.New(sha256.New, m)
	h.Write([]byte(namespace))
	h.Write([]byte("|"))
	h.Write([]byte(strings.ToLower(strings.TrimSpace(purpose))))
	return h.Sum(nil)
}

// Encrypt performs AES-256-GCM encryption using a derived key for the namespace.
// Returns an envelope string: "aegis:v1:" + base64(nonce|ciphertext).
func Encrypt(namespace string, plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", errors.New("empty plaintext")
	}
	key := kdf(namespace, "enc")
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aegis encrypt: cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("aegis encrypt: gcm init failed: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("aegis encrypt: nonce gen failed: %w", err)
	}
	// Seal appends tag to ciphertext.
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	buf := append(nonce, ciphertext...)
	return "aegis:v1:" + base64.StdEncoding.EncodeToString(buf), nil
}

// Decrypt performs AES-256-GCM decryption using the derived key for the namespace.
// Accepts envelopes produced by Encrypt.
func Decrypt(namespace string, envelope string) ([]byte, error) {
	enc := strings.TrimSpace(envelope)
	if enc == "" {
		return nil, errors.New("empty ciphertext")
	}
	enc = strings.TrimPrefix(enc, "aegis:v1:")
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return nil, fmt.Errorf("aegis decrypt: b64 decode failed: %w", err)
	}
	key := kdf(namespace, "enc")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aegis decrypt: cipher init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aegis decrypt: gcm init failed: %w", err)
	}
	ns := gcm.NonceSize()
	if len(raw) < ns+gcm.Overhead() {
		return nil, errors.New("aegis decrypt: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("aegis decrypt: open failed: %w", err)
	}
	return pt, nil
}

// HMAC computes HMAC-SHA256 using a derived key for the namespace and returns a hex string.
func HMAC(namespace string, input []byte) (string, error) {
	key := kdf(namespace, "hmac")
	h := hmac.New(sha256.New, key)
	h.Write(input)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Allowed indicates whether the role set satisfies any of the allowed roles.
// Utility for simple role checks inside agents.
func Allowed(userRoles []string, allowedRoles ...string) bool {
	if len(allowedRoles) == 0 {
		return true
	}
	set := map[string]struct{}{}
	for _, r := range userRoles {
		set[strings.ToLower(strings.TrimSpace(r))] = struct{}{}
	}
	for _, a := range allowedRoles {
		if _, ok := set[strings.ToLower(strings.TrimSpace(a))]; ok {
			return true
		}
	}
	return false
}
