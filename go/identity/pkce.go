package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// PKCE is a Proof Key for Code Exchange pair (RFC 7636).
//
// The Verifier stays with the caller — in a server-side session, never in the
// URL — and the Challenge goes to the authorization endpoint. At Exchange the
// provider hashes the Verifier and compares. Without this, anyone who
// intercepts an authorization code can redeem it.
type PKCE struct {
	// Verifier is the secret half. Keep it; pass it to Exchange.
	Verifier string
	// Challenge is base64url(sha256(Verifier)), unpadded.
	Challenge string
	// Method is always "S256". The spec advertises no other, and "plain" is
	// not a fallback worth having: it protects against nothing.
	Method string
}

// NewPKCE generates a fresh verifier/challenge pair.
func NewPKCE() (PKCE, error) {
	// 32 random bytes → 43 base64url characters, comfortably inside RFC 7636's
	// 43–128 range and at the top of its entropy recommendation.
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return PKCE{}, fmt.Errorf("identity: pkce: %w", err)
	}
	verifier := b64.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{
		Verifier:  verifier,
		Challenge: b64.EncodeToString(sum[:]),
		Method:    "S256",
	}, nil
}

// NewState generates a random value for AuthorizeParams.State or .Nonce.
//
// Both are single-use, unguessable and compared on the way back: state against
// what the caller stored, nonce against the id_token's claim.
func NewState() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("identity: state: %w", err)
	}
	return b64.EncodeToString(buf), nil
}
