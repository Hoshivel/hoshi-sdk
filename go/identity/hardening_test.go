package identity

import (
	"context"
	"testing"
	"time"
)

func TestUserInfoValidateSubject(t *testing.T) {
	id := IDToken{Subject: "usr_1"}
	if err := (UserInfo{Subject: "usr_1"}).ValidateSubject(id); err != nil {
		t.Fatal(err)
	}
	if err := (UserInfo{Subject: "usr_2"}).ValidateSubject(id); err == nil {
		t.Fatal("mismatched subjects must be rejected")
	}
}

// A withdrawn signing key must stop being accepted.
//
// This is the failure a cache that only refetches for unknown kids has: the
// process verified a token under some kid, so it holds that key; the provider
// then stops publishing it; and nothing ever asks again. Signature verification
// keeps succeeding for as long as the process runs, which makes revoking a key
// at the provider a change the holder of an old token never sees.
func TestWithdrawnSigningKeyStopsBeingAccepted(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	now := time.Now()
	c.now = func() time.Time { return now }

	token := signToken(t, testKID, validClaims(p.URL))
	if _, err := c.VerifyIDToken(context.Background(), token, "n-1"); err != nil {
		t.Fatalf("the token must verify while its key is published: %v", err)
	}
	if got := p.jwksHits.Load(); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1", got)
	}

	// The provider withdraws the key: its JWKS now publishes a different kid,
	// so the one that signed the token is no longer among the current keys.
	p.kid = "key-2"

	// Inside the cache's lifetime the old answer still stands. That is the
	// deliberate cost of caching at all, and it is why the window is bounded.
	if _, err := c.VerifyIDToken(context.Background(), token, "n-1"); err != nil {
		t.Fatalf("within jwksMaxAge the cached key still answers: %v", err)
	}

	now = now.Add(jwksMaxAge + time.Second)
	if _, err := c.VerifyIDToken(context.Background(), token, "n-1"); err == nil {
		t.Fatal("a key the provider no longer publishes was still accepted")
	}
	if got := p.jwksHits.Load(); got != 2 {
		t.Fatalf("the stale set must be re-fetched exactly once: JWKS fetches = %d, want 2", got)
	}
}

// An unreachable provider must not turn an expired key set back into a usable
// one. Rejecting is the safe direction: the client cannot tell a key that is
// still published from one that has been withdrawn, and treating "I could not
// ask" as "still valid" is what the expiry exists to prevent.
func TestStaleKeysAreNotServedWhenTheProviderIsUnreachable(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	now := time.Now()
	c.now = func() time.Time { return now }

	token := signToken(t, testKID, validClaims(p.URL))
	if _, err := c.VerifyIDToken(context.Background(), token, "n-1"); err != nil {
		t.Fatal(err)
	}

	p.Close()
	now = now.Add(jwksMaxAge + time.Second)

	if _, err := c.VerifyIDToken(context.Background(), token, "n-1"); err == nil {
		t.Fatal("an expired key set answered because the provider could not be reached")
	}

	// The next token must not become another outbound request: a provider that
	// is down would otherwise be asked once per token presented.
	before := p.jwksHits.Load()
	if _, err := c.VerifyIDToken(context.Background(), token, "n-1"); err == nil {
		t.Fatal("still accepted on the second attempt")
	}
	if got := p.jwksHits.Load(); got != before {
		t.Fatalf("a rate-limited retry reached the provider: hits %d -> %d", before, got)
	}
}

// Rotation must stay transparent: a key the provider has *added* is picked up
// without waiting for the cache to expire, because an unknown kid still
// triggers a fetch.
func TestNewlyPublishedKeyIsPickedUpWithoutWaiting(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	now := time.Now()
	c.now = func() time.Time { return now }

	if _, err := c.VerifyIDToken(context.Background(), signToken(t, testKID, validClaims(p.URL)), "n-1"); err != nil {
		t.Fatal(err)
	}

	p.kid = "key-2"
	now = now.Add(jwksRefetchInterval + time.Second)

	rotated := signToken(t, "key-2", validClaims(p.URL))
	if _, err := c.VerifyIDToken(context.Background(), rotated, "n-1"); err != nil {
		t.Fatalf("a newly published key must be picked up before jwksMaxAge: %v", err)
	}
}
