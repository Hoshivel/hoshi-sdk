package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testKey is generated once: 2048-bit RSA generation is slow enough that doing
// it per test would dominate the suite's runtime.
var testKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}()

const testKID = "key-1"

// provider is a stand-in OIDC provider. It serves a real discovery document, a real
// JWKS built from testKey, and real signatures — so the tests exercise the same
// path a live provider would, not a mock that agrees with the client by
// construction.
type provider struct {
	*httptest.Server
	jwksHits  atomic.Int32
	discHits  atomic.Int32
	kid       string
	tokenForm url.Values
	authUser  string
	authPass  string
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	p := &provider{kid: testKID}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		p.discHits.Add(1)
		base := p.URL
		writeJSON(w, 200, map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/oauth/authorize",
			"token_endpoint":                        base + "/oauth/token",
			"userinfo_endpoint":                     base + "/oauth/userinfo",
			"jwks_uri":                              base + "/oauth/jwks.json",
			"revocation_endpoint":                   base + "/oauth/revoke",
			"introspection_endpoint":                base + "/oauth/introspect",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported":      []string{"S256"},
			"scopes_supported":                      []string{"openid", "profile", "email", "roles"},
			// Three deliberately different lists. Equal ones would let a field
			// that reads the wrong key still pass.
			"token_endpoint_auth_methods_supported":         []string{"client_secret_basic"},
			"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "none"},
			"introspection_endpoint_auth_methods_supported": []string{"client_secret_post"},
		})
	})

	mux.HandleFunc("GET /oauth/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		p.jwksHits.Add(1)
		pub := testKey.Public().(*rsa.PublicKey)
		writeJSON(w, 200, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": p.kid, "use": "sig", "alg": "RS256",
			"n": b64.EncodeToString(pub.N.Bytes()),
			"e": b64.EncodeToString([]byte{0x01, 0x00, 0x01}),
		}}})
	})

	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.tokenForm = r.PostForm
		p.authUser, p.authPass, _ = r.BasicAuth()
		if r.PostForm.Get("code") == "bad-code" {
			writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{
			"access_token": "at_live", "token_type": "Bearer", "expires_in": 3600,
			"refresh_token": "rt_live", "scope": "openid profile email roles",
		})
	})

	mux.HandleFunc("/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at_live" {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeJSON(w, 401, map[string]any{"error": "invalid_token"})
			return
		}
		writeJSON(w, 200, map[string]any{
			"sub": "usr_1", "email": "ann@example.com", "email_verified": true,
			"name": "Ann", "roles": []string{"billing.admin"},
			"department": "ops", // 下游服務加的 claim，UserInfoRaw 才看得到
		})
	})

	mux.HandleFunc("POST /oauth/introspect", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("token") != "at_live" {
			writeJSON(w, 200, map[string]any{"active": false})
			return
		}
		writeJSON(w, 200, map[string]any{
			"active": true, "sub": "usr_1", "client_id": "test-client",
			"scope": "openid profile", "exp": time.Now().Add(time.Hour).Unix(),
			"token_type": "Bearer",
		})
	})

	mux.HandleFunc("POST /oauth/revoke", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	})

	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func newClient(t *testing.T, p *provider) *Client {
	t.Helper()
	return &Client{Issuer: p.URL, ClientID: "test-client", ClientSecret: "test-secret"}
}

// signToken builds a real RS256 JWT with the given claims.
func signToken(t *testing.T, kid string, claims map[string]any) string {
	t.Helper()
	return signTokenWith(t, testKey, "RS256", kid, claims)
}

func signTokenWith(t *testing.T, key *rsa.PrivateKey, alg, kid string, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": alg, "kid": kid, "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signing := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64.EncodeToString(sig)
}

// validClaims is a token that should verify, so each test can mutate one field
// and assert that the single change is what makes it fail.
func validClaims(issuer string) map[string]any {
	return map[string]any{
		"iss": issuer, "sub": "usr_1", "aud": "test-client",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"nonce": "n-1", "email": "ann@example.com", "email_verified": true,
		"name": "Ann", "roles": []string{"billing.admin"},
	}
}

// ---- discovery -------------------------------------------------------------

func TestDiscoverCachesAndValidatesIssuer(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	ctx := context.Background()

	doc, err := c.Discover(ctx)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if doc.TokenEndpoint != p.URL+"/oauth/token" {
		t.Errorf("token endpoint = %q", doc.TokenEndpoint)
	}
	if _, err := c.Discover(ctx); err != nil {
		t.Fatalf("second Discover: %v", err)
	}
	if got := p.discHits.Load(); got != 1 {
		t.Errorf("discovery fetched %d times, want 1 (should be cached)", got)
	}
}

func TestDiscoverReadsEachEndpointsAuthMethods(t *testing.T) {
	// A provider may accept different client authentication at each endpoint,
	// so the three lists are three fields. The fixture serves three different
	// values: reading the token endpoint's list for all of them, or crossing
	// two tags, changes the result here.
	p := newProvider(t)
	c := newClient(t, p)

	doc, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, tc := range []struct {
		name string
		got  []string
		want []string
	}{
		{"token", doc.TokenEndpointAuthMethodsSupported, []string{"client_secret_basic"}},
		{"revocation", doc.RevocationEndpointAuthMethodsSupported, []string{"client_secret_basic", "none"}},
		{"introspection", doc.IntrospectionEndpointAuthMethodsSupported, []string{"client_secret_post"}},
	} {
		if !slices.Equal(tc.got, tc.want) {
			t.Errorf("%s endpoint auth methods = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

func TestDiscoverRejectsIssuerMismatch(t *testing.T) {
	// A document that names a different issuer must not become the basis for
	// verifying tokens, however it came to be served from this address.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"issuer": "https://elsewhere.example.com"})
	}))
	defer srv.Close()

	c := &Client{Issuer: srv.URL}
	if _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("expected an error when the discovery issuer does not match")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDiscoverRejectsEndpointsOffTheIssuersOrigin(t *testing.T) {
	// The issuer matches; one endpoint does not. This is the shape that matters
	// — a document that keeps the right name and moves the token exchange, which
	// carries the client secret and the authorization code, to somebody else.
	for _, field := range []string{
		"authorization_endpoint", "token_endpoint", "userinfo_endpoint",
		"jwks_uri", "revocation_endpoint", "introspection_endpoint",
		"end_session_endpoint",
	} {
		t.Run(field, func(t *testing.T) {
			var base string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				doc := map[string]any{
					"issuer":                 base,
					"authorization_endpoint": base + "/oauth/authorize",
					"token_endpoint":         base + "/oauth/token",
					"userinfo_endpoint":      base + "/oauth/userinfo",
					"jwks_uri":               base + "/oauth/jwks.json",
					"revocation_endpoint":    base + "/oauth/revoke",
					"introspection_endpoint": base + "/oauth/introspect",
					"end_session_endpoint":   base + "/oauth/logout",
				}
				doc[field] = "https://attacker.example.com/oauth/collect"
				writeJSON(w, 200, doc)
			}))
			defer srv.Close()
			base = srv.URL

			c := &Client{Issuer: srv.URL, ClientID: "test-client", ClientSecret: "test-secret"}
			_, err := c.Discover(context.Background())
			if err == nil {
				t.Fatalf("%s pointing off the issuer's origin must be refused", field)
			}
			if !strings.Contains(err.Error(), field) ||
				!strings.Contains(err.Error(), "issuer's origin") {
				t.Errorf("the error must name the offending field: %v", err)
			}
		})
	}
}

func TestDiscoverAllowsAbsentOptionalEndpoints(t *testing.T) {
	// A provider that advertises less is not a provider that has been tampered
	// with. The missing endpoint fails at the call that needs it, not here.
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer":                 base,
			"authorization_endpoint": base + "/oauth/authorize",
			"token_endpoint":         base + "/oauth/token",
			"userinfo_endpoint":      base + "/oauth/userinfo",
			"jwks_uri":               base + "/oauth/jwks.json",
		})
	}))
	defer srv.Close()
	base = srv.URL

	c := &Client{Issuer: srv.URL, ClientID: "test-client"}
	if _, err := c.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, err := c.EndSessionURL(context.Background(), LogoutParams{}); err == nil {
		t.Fatal("an endpoint the provider never advertised must fail where it is used")
	}
}

// ---- authorize + PKCE ------------------------------------------------------

func TestNewPKCEChallengeMatchesVerifier(t *testing.T) {
	pkce, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(pkce.Verifier))
	if want := b64.EncodeToString(sum[:]); pkce.Challenge != want {
		t.Errorf("challenge = %q, want %q", pkce.Challenge, want)
	}
	if pkce.Method != "S256" {
		t.Errorf("method = %q, want S256", pkce.Method)
	}
	if len(pkce.Verifier) < 43 {
		t.Errorf("verifier is %d characters, RFC 7636 wants at least 43", len(pkce.Verifier))
	}
}

func TestAuthorizeURL(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	pkce, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}

	raw, err := c.AuthorizeURL(context.Background(), AuthorizeParams{
		RedirectURI: "https://app.example.com/callback",
		Scopes:      []string{ScopeEmail},
		State:       "st-1",
		Challenge:   pkce,
		Nonce:       "n-1",
	})
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()

	for key, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "test-client",
		"redirect_uri":          "https://app.example.com/callback",
		"state":                 "st-1",
		"nonce":                 "n-1",
		"code_challenge":        pkce.Challenge,
		"code_challenge_method": "S256",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	// openid is required for an OIDC flow, so it is added rather than left to
	// the caller to remember.
	if scope := q.Get("scope"); !strings.Contains(scope, "openid") || !strings.Contains(scope, "email") {
		t.Errorf("scope = %q, want it to contain openid and email", scope)
	}
}

func TestAuthorizeURLRequiresStateAndChallenge(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	pkce, _ := NewPKCE()
	ctx := context.Background()

	cases := map[string]AuthorizeParams{
		"missing state":       {RedirectURI: "https://a.example.com/cb", Challenge: pkce},
		"missing challenge":   {RedirectURI: "https://a.example.com/cb", State: "st"},
		"missing redirectURI": {State: "st", Challenge: pkce},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := c.AuthorizeURL(ctx, params); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}

// ---- token endpoint --------------------------------------------------------

func TestExchangeSendsPKCEAndBasicAuth(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)

	tok, err := c.Exchange(context.Background(), "ac_1", "https://app.example.com/cb", "verifier-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if tok.AccessToken != "at_live" || tok.RefreshToken != "rt_live" {
		t.Errorf("unexpected tokens: %+v", tok)
	}
	if got := tok.Scopes(); len(got) != 4 {
		t.Errorf("Scopes() = %v, want 4 entries", got)
	}

	for key, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "ac_1",
		"redirect_uri":  "https://app.example.com/cb",
		"code_verifier": "verifier-1",
	} {
		if got := p.tokenForm.Get(key); got != want {
			t.Errorf("form %s = %q, want %q", key, got, want)
		}
	}
	// The secret goes in the Authorization header, not the body, so it stays
	// out of anything that logs post data.
	if p.authUser != "test-client" || p.authPass != "test-secret" {
		t.Errorf("basic auth = %q/%q, want test-client/test-secret", p.authUser, p.authPass)
	}
	if p.tokenForm.Get("client_secret") != "" {
		t.Error("client_secret must not be sent in the form body")
	}
}

func TestExchangeSurfacesOAuthError(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)

	_, err := c.Exchange(context.Background(), "bad-code", "https://app.example.com/cb", "v")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !Is(err, ErrCodeInvalidGrant) {
		t.Errorf("Is(err, invalid_grant) = false, err = %v", err)
	}
}

func TestRefresh(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)

	if _, err := c.Refresh(context.Background(), "rt_live"); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got := p.tokenForm.Get("grant_type"); got != "refresh_token" {
		t.Errorf("grant_type = %q, want refresh_token", got)
	}
	if got := p.tokenForm.Get("refresh_token"); got != "rt_live" {
		t.Errorf("refresh_token = %q", got)
	}
}

// ---- userinfo / introspect / revoke ----------------------------------------

func TestUserInfo(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)

	info, err := c.UserInfo(context.Background(), "at_live")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info.Subject != "usr_1" || info.Email != "ann@example.com" || !info.EmailVerified {
		t.Errorf("unexpected claims: %+v", info)
	}
	if !info.HasRole("billing.admin") {
		t.Error("HasRole(billing.admin) = false")
	}
	if info.HasRole("platform_admin") {
		t.Error("HasRole(platform_admin) = true, but the user does not hold it")
	}
}

func TestUserInfoRawKeepsUnknownClaims(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)

	raw, err := c.UserInfoRaw(context.Background(), "at_live")
	if err != nil {
		t.Fatalf("UserInfoRaw: %v", err)
	}
	// A downstream service's own claim survives the round trip; the typed
	// struct would silently drop it.
	if raw["department"] != "ops" {
		t.Errorf("department = %v, want ops", raw["department"])
	}
}

func TestUserInfoRejectsBadToken(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)

	_, err := c.UserInfo(context.Background(), "at_wrong")
	if !Is(err, ErrCodeInvalidToken) {
		t.Errorf("Is(err, invalid_token) = false, err = %v", err)
	}
}

func TestIntrospect(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	ctx := context.Background()

	active, err := c.Introspect(ctx, "at_live")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !active.Active || active.Subject != "usr_1" {
		t.Errorf("unexpected introspection: %+v", active)
	}

	// An unknown token is a successful query with a negative answer, not an
	// error — the endpoint is not an oracle for which tokens exist.
	inactive, err := c.Introspect(ctx, "at_unknown")
	if err != nil {
		t.Fatalf("Introspect(unknown): %v", err)
	}
	if inactive.Active {
		t.Error("unknown token reported active")
	}
	if inactive.Subject != "" {
		t.Errorf("inactive result leaked a subject: %q", inactive.Subject)
	}
}

func TestRevoke(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	if err := c.Revoke(context.Background(), "at_live"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}

// ---- id_token verification -------------------------------------------------

func TestVerifyIDToken(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)

	tok, err := c.VerifyIDToken(context.Background(), signToken(t, testKID, validClaims(p.URL)), "n-1")
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if tok.Subject != "usr_1" {
		t.Errorf("sub = %q", tok.Subject)
	}
	if !tok.HasRole("billing.admin") {
		t.Error("HasRole(billing.admin) = false")
	}
	if tok.Raw["email"] != "ann@example.com" {
		t.Errorf("Raw[email] = %v", tok.Raw["email"])
	}
}

// TestVerifyIDTokenRejects walks the checks one at a time: each case starts
// from a token that verifies and breaks exactly one thing, so a passing case
// proves that specific check is what rejected it.
func TestVerifyIDTokenRejects(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	ctx := context.Background()

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token func() string
		nonce string
		want  string
	}{
		{
			name:  "not a JWT",
			token: func() string { return "not.a" },
			nonce: "n-1",
			want:  "three-part",
		},
		{
			name: "alg is not RS256",
			token: func() string {
				// "none" and HMAC confusion both arrive as an unexpected alg,
				// and the algorithm is our decision rather than the token's.
				return signTokenWith(t, testKey, "none", testKID, validClaims(p.URL))
			},
			nonce: "n-1",
			want:  "alg",
		},
		{
			name: "signed by a key the provider does not publish",
			token: func() string {
				return signTokenWith(t, otherKey, "RS256", testKID, validClaims(p.URL))
			},
			nonce: "n-1",
			want:  "signature does not verify",
		},
		{
			name: "unknown kid",
			token: func() string {
				return signToken(t, "key-does-not-exist", validClaims(p.URL))
			},
			nonce: "n-1",
			want:  "unknown key",
		},
		{
			name: "wrong issuer",
			token: func() string {
				cl := validClaims(p.URL)
				cl["iss"] = "https://elsewhere.example.com"
				return signToken(t, testKID, cl)
			},
			nonce: "n-1",
			want:  "iss",
		},
		{
			// IDTokenClaims verification step 6. It is absent from the older
			// "iss/aud/exp/nonce" shorthand, which is exactly why a
			// reimplementation is likely to skip it.
			name: "no sub claim",
			token: func() string {
				cl := validClaims(p.URL)
				delete(cl, "sub")
				return signToken(t, testKID, cl)
			},
			nonce: "n-1",
			want:  "sub",
		},
		{
			// IDTokenClaims verification step 7.
			name: "no iat claim",
			token: func() string {
				cl := validClaims(p.URL)
				delete(cl, "iat")
				return signToken(t, testKID, cl)
			},
			nonce: "n-1",
			want:  "iat",
		},
		{
			// Steps 9 and 10: a multi-audience token without azp cannot say
			// which client asked for it, so one audience could present it to
			// another.
			name: "multiple audiences without azp",
			token: func() string {
				cl := validClaims(p.URL)
				cl["aud"] = []string{"another-client", "test-client"}
				return signToken(t, testKID, cl)
			},
			nonce: "n-1",
			want:  "azp",
		},
		{
			name: "azp names a different client",
			token: func() string {
				cl := validClaims(p.URL)
				cl["azp"] = "someone-else"
				return signToken(t, testKID, cl)
			},
			nonce: "n-1",
			want:  "azp",
		},
		{
			name: "audience is another client",
			token: func() string {
				cl := validClaims(p.URL)
				cl["aud"] = "someone-else"
				return signToken(t, testKID, cl)
			},
			nonce: "n-1",
			want:  "aud",
		},
		{
			name: "expired",
			token: func() string {
				cl := validClaims(p.URL)
				cl["exp"] = time.Now().Add(-time.Hour).Unix()
				return signToken(t, testKID, cl)
			},
			nonce: "n-1",
			want:  "expired",
		},
		{
			name: "issued in the future",
			token: func() string {
				cl := validClaims(p.URL)
				cl["iat"] = time.Now().Add(time.Hour).Unix()
				return signToken(t, testKID, cl)
			},
			nonce: "n-1",
			want:  "future",
		},
		{
			name: "nonce belongs to another login",
			token: func() string {
				return signToken(t, testKID, validClaims(p.URL))
			},
			nonce: "n-2",
			want:  "nonce",
		},
		{
			name: "nonce present when none was sent",
			token: func() string {
				return signToken(t, testKID, validClaims(p.URL))
			},
			nonce: "",
			want:  "nonce",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.VerifyIDToken(ctx, tc.token(), tc.nonce)
			if err == nil {
				t.Fatal("token verified but should have been rejected")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestVerifyIDTokenAcceptsAudienceArray(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)

	cl := validClaims(p.URL)
	cl["aud"] = []string{"another-client", "test-client"}
	cl["azp"] = "test-client"
	if _, err := c.VerifyIDToken(context.Background(), signToken(t, testKID, cl), "n-1"); err != nil {
		t.Fatalf("aud as an array should verify: %v", err)
	}
}

func TestJWKSRefetchIsRateLimited(t *testing.T) {
	p := newProvider(t)
	c := newClient(t, p)
	ctx := context.Background()

	// Prime the cache.
	if _, err := c.VerifyIDToken(ctx, signToken(t, testKID, validClaims(p.URL)), "n-1"); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if got := p.jwksHits.Load(); got != 1 {
		t.Fatalf("jwks fetched %d times, want 1", got)
	}

	// A burst of tokens carrying invented kids must not become a burst of
	// outbound fetches: that would let anyone who can present a token drive
	// this process's traffic to the provider.
	for range 5 {
		_, err := c.VerifyIDToken(ctx, signToken(t, "made-up", validClaims(p.URL)), "n-1")
		if err == nil {
			t.Fatal("a token with an unknown kid should not verify")
		}
	}
	if got := p.jwksHits.Load(); got != 1 {
		t.Errorf("jwks fetched %d times after 5 unknown kids, want 1", got)
	}

	// Once the interval has passed, a genuine rotation is picked up.
	c.mu.Lock()
	c.keys.fetchedAt = time.Now().Add(-2 * jwksRefetchInterval)
	c.mu.Unlock()
	p.kid = "key-2"

	if _, err := c.VerifyIDToken(ctx, signToken(t, "key-2", validClaims(p.URL)), "n-1"); err != nil {
		t.Fatalf("rotated key should verify after the refetch interval: %v", err)
	}
	if got := p.jwksHits.Load(); got != 2 {
		t.Errorf("jwks fetched %d times, want 2", got)
	}
}
