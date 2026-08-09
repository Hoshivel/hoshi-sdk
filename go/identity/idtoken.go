package identity

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// clockSkew is how much disagreement between this host's clock and the
// provider's is tolerated when checking exp/iat. Small, but not zero: rejecting
// a token because two machines are a second apart is a fault with no cause an
// operator can find.
const clockSkew = 2 * time.Minute

// jwksRefetchInterval bounds how often an unknown kid triggers a JWKS fetch.
//
// Refetching on an unknown kid is what makes key rotation transparent. Doing it
// without a bound hands anyone who can present a token a way to make this
// process hammer the provider: a stream of tokens carrying invented kids would
// become a stream of outbound requests. Between fetches an unknown kid is
// simply rejected, which is the correct answer for a forged one anyway.
const jwksRefetchInterval = time.Minute

// IDToken is the verified content of an id_token. It is only ever returned by
// VerifyIDToken, so a value of this type has had its signature and claims
// checked — there is no way to obtain one without that happening.
type IDToken struct {
	Subject         string
	Issuer          string
	Audience        []string
	AuthorizedParty string
	Expiry          time.Time
	IssuedAt        time.Time
	AuthTime        time.Time
	Nonce           string
	Email           string
	EmailVerified   bool
	Name            string
	Locale          string
	Roles           []string
	// Raw is every claim as decoded, for claims a downstream service added.
	Raw map[string]any
}

// HasRole reports whether the token's roles include role.
func (t IDToken) HasRole(role string) bool {
	for _, held := range t.Roles {
		if held == role {
			return true
		}
	}
	return false
}

// jwtHeader is the JOSE header this package accepts.
type jwtHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// claims mirrors the registered claims, with the flexible ones left as raw
// JSON because "aud" is a string or an array depending on the issuer.
type claims struct {
	Issuer          string          `json:"iss"`
	Subject         string          `json:"sub"`
	Audience        json.RawMessage `json:"aud"`
	AuthorizedParty string          `json:"azp"`
	Expiry          int64           `json:"exp"`
	IssuedAt        int64           `json:"iat"`
	AuthTime        int64           `json:"auth_time"`
	Nonce           string          `json:"nonce"`
	Email           string          `json:"email"`
	EmailVerified   bool            `json:"email_verified"`
	Name            string          `json:"name"`
	Locale          string          `json:"locale"`
	Roles           []string        `json:"roles"`
}

// VerifyIDToken checks an id_token's signature and claims and returns its
// content.
//
// nonce must be the value passed to AuthorizeURL for this login; pass "" only
// when none was sent. Supplying it is what stops an id_token obtained in one
// session from being replayed into another.
//
// The checks, in order: the token parses; alg is RS256; the signing key is
// known; the signature verifies; iss matches the configured issuer; aud
// contains this client; the token has not expired and was not issued in the
// future; the nonce matches.
func (c *Client) VerifyIDToken(ctx context.Context, idToken, nonce string) (IDToken, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return IDToken{}, errors.New("identity: id_token is not a three-part JWT")
	}

	headerJSON, err := b64.DecodeString(parts[0])
	if err != nil {
		return IDToken{}, fmt.Errorf("identity: id_token header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return IDToken{}, fmt.Errorf("identity: id_token header: %w", err)
	}
	// Only RS256. Accepting whatever the token names is how "alg": "none" and
	// the HMAC-with-the-public-key confusion get in; the algorithm is our
	// decision, not the token's.
	if header.Algorithm != "RS256" {
		return IDToken{}, fmt.Errorf("identity: id_token alg is %q, want RS256", header.Algorithm)
	}

	payloadJSON, err := b64.DecodeString(parts[1])
	if err != nil {
		return IDToken{}, fmt.Errorf("identity: id_token payload: %w", err)
	}
	signature, err := b64.DecodeString(parts[2])
	if err != nil {
		return IDToken{}, fmt.Errorf("identity: id_token signature: %w", err)
	}

	key, err := c.signingKey(ctx, header.KeyID)
	if err != nil {
		return IDToken{}, err
	}
	signed := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, signed[:], signature); err != nil {
		return IDToken{}, fmt.Errorf("identity: id_token signature does not verify: %w", err)
	}

	var cl claims
	if err := json.Unmarshal(payloadJSON, &cl); err != nil {
		return IDToken{}, fmt.Errorf("identity: id_token claims: %w", err)
	}

	issuer := strings.TrimRight(c.Issuer, "/")
	if cl.Issuer != issuer {
		return IDToken{}, fmt.Errorf("identity: id_token iss is %q, want %q", cl.Issuer, issuer)
	}

	if cl.Subject == "" {
		return IDToken{}, errors.New("identity: id_token has no sub claim")
	}
	if cl.IssuedAt == 0 {
		return IDToken{}, errors.New("identity: id_token has no iat claim")
	}

	audience, err := parseAudience(cl.Audience)
	if err != nil {
		return IDToken{}, err
	}
	if c.ClientID != "" && !contains(audience, c.ClientID) {
		return IDToken{}, fmt.Errorf("identity: id_token aud %v does not include %q", audience, c.ClientID)
	}
	if len(audience) > 1 && cl.AuthorizedParty == "" {
		return IDToken{}, errors.New("identity: id_token with multiple audiences has no azp claim")
	}
	if cl.AuthorizedParty != "" && c.ClientID != "" && cl.AuthorizedParty != c.ClientID {
		return IDToken{}, fmt.Errorf("identity: id_token azp is %q, want %q", cl.AuthorizedParty, c.ClientID)
	}

	now := c.clock()
	if cl.Expiry == 0 {
		return IDToken{}, errors.New("identity: id_token has no exp claim")
	}
	if expiry := time.Unix(cl.Expiry, 0); now.After(expiry.Add(clockSkew)) {
		return IDToken{}, fmt.Errorf("identity: id_token expired at %s", expiry.UTC().Format(time.RFC3339))
	}
	if cl.IssuedAt != 0 {
		if issued := time.Unix(cl.IssuedAt, 0); issued.After(now.Add(clockSkew)) {
			return IDToken{}, fmt.Errorf("identity: id_token was issued in the future (%s)",
				issued.UTC().Format(time.RFC3339))
		}
	}
	if cl.Nonce != nonce {
		// Both directions matter: a missing nonce when one was sent means the
		// token belongs to a different login, and a present one when none was
		// sent means it belongs to a login we did not start.
		return IDToken{}, errors.New("identity: id_token nonce does not match the one sent")
	}

	raw := map[string]any{}
	_ = json.Unmarshal(payloadJSON, &raw)

	out := IDToken{
		Subject:         cl.Subject,
		Issuer:          cl.Issuer,
		Audience:        audience,
		AuthorizedParty: cl.AuthorizedParty,
		Expiry:          time.Unix(cl.Expiry, 0),
		Nonce:           cl.Nonce,
		Email:           cl.Email,
		EmailVerified:   cl.EmailVerified,
		Name:            cl.Name,
		Locale:          cl.Locale,
		Roles:           cl.Roles,
		Raw:             raw,
	}
	if cl.IssuedAt != 0 {
		out.IssuedAt = time.Unix(cl.IssuedAt, 0)
	}
	if cl.AuthTime != 0 {
		out.AuthTime = time.Unix(cl.AuthTime, 0)
	}
	return out, nil
}

// parseAudience accepts "aud" as either a string or an array of strings, which
// both appear in the wild.
func parseAudience(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("identity: id_token has no aud claim")
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, nil
	}
	return nil, errors.New("identity: id_token aud is neither a string nor an array of strings")
}

// keySet is a cached JWKS.
type keySet struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// jwksDoc is the wire form of a JSON Web Key Set.
type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// signingKey returns the public key for kid, fetching the JWKS if the key is
// not cached and a fetch is not rate-limited.
func (c *Client) signingKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	cached := c.keys
	c.mu.Unlock()

	if cached != nil {
		if key, ok := cached.keys[kid]; ok {
			return key, nil
		}
		if c.clock().Sub(cached.fetchedAt) < jwksRefetchInterval {
			return nil, fmt.Errorf("identity: id_token signed by unknown key %q", kid)
		}
	}

	fetched, err := c.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}
	key, ok := fetched.keys[kid]
	if !ok {
		return nil, fmt.Errorf("identity: id_token signed by unknown key %q", kid)
	}
	return key, nil
}

func (c *Client) fetchJWKS(ctx context.Context) (*keySet, error) {
	doc, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	var raw jwksDoc
	if err := c.getJSON(ctx, doc.JWKSURI, "", &raw); err != nil {
		return nil, fmt.Errorf("identity: jwks: %w", err)
	}

	set := &keySet{keys: make(map[string]*rsa.PublicKey, len(raw.Keys)), fetchedAt: c.clock()}
	for _, jwk := range raw.Keys {
		// Skip anything that is not an RSA signing key rather than failing the
		// whole fetch: a provider may publish keys for purposes we do not use,
		// and one of those must not take the usable keys down with it.
		if jwk.Kty != "RSA" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		key, err := rsaPublicKey(jwk.N, jwk.E)
		if err != nil {
			continue
		}
		set.keys[jwk.Kid] = key
	}
	if len(set.keys) == 0 {
		return nil, errors.New("identity: jwks contains no usable RSA signing keys")
	}

	c.mu.Lock()
	c.keys = set
	c.mu.Unlock()
	return set, nil
}

// rsaPublicKey rebuilds a public key from a JWK's base64url modulus and
// exponent.
func rsaPublicKey(nRaw, eRaw string) (*rsa.PublicKey, error) {
	nBytes, err := b64.DecodeString(nRaw)
	if err != nil {
		return nil, fmt.Errorf("jwk modulus: %w", err)
	}
	eBytes, err := b64.DecodeString(eRaw)
	if err != nil {
		return nil, fmt.Errorf("jwk exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 {
		return nil, errors.New("jwk is missing modulus or exponent")
	}
	exponent := new(big.Int).SetBytes(eBytes)
	if !exponent.IsInt64() || exponent.Int64() > 1<<31-1 || exponent.Int64() < 3 {
		return nil, errors.New("jwk exponent is out of range")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(exponent.Int64()),
	}, nil
}
