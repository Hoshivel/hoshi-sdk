// Package identity is an OpenID Connect relying-party client: the caller side
// of an OIDC provider, built against the published specifications rather than
// any one provider's quirks.
//
// The package covers the machine-to-machine surface: discovery, the token
// endpoint, userinfo, introspection, revocation, and RS256 verification of an
// id_token. The browser flow is the caller's own — AuthorizeURL builds the URL
// to send a browser to, and Exchange takes the code that comes back.
//
// # Two things this package refuses to let you skip
//
// Endpoints always come from discovery. Nothing here lets you hardcode
// "/oauth/token": a path written into a caller keeps working right up until the
// deployment shape changes, and then fails somewhere far from the cause. What
// discovery says is checked before it is used — the document must name the
// issuer it was fetched for, and every endpoint in it must live on that
// issuer's own origin.
//
// An id_token is verified before its claims are returned. VerifyIDToken checks
// the RS256 signature against the provider's JWKS and then the issuer,
// audience, expiry and nonce. Holding a token is not the same as having checked
// one, and a package that returned unverified claims would make the difference
// invisible at the call site.
//
// Zero dependencies, standard library only.
package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds a single call to the provider.
const DefaultTimeout = 15 * time.Second

// discoveryTTL is how long a fetched discovery document is reused. The document
// changes only when the deployment does, so this is about not making one HTTP
// request per token exchange rather than about freshness.
const discoveryTTL = 15 * time.Minute

// maxBodyBytes caps a response body. Discovery documents and token responses
// are small; a JWKS with many keys is still tiny.
const maxBodyBytes = 1 << 20

// Scopes defined by OpenID Connect, plus the "roles" scope that providers
// commonly use to return a user's role list.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeRoles         = "roles"
	ScopeOfflineAccess = "offline_access"
)

// Client talks to one OIDC provider. The zero value is not usable; set at
// least Issuer. ClientID and ClientSecret are required for the endpoints that
// authenticate a client (token, introspect, revoke).
//
// A Client is safe for concurrent use and caches discovery and signing keys, so
// callers should keep one around rather than building one per request.
type Client struct {
	// Issuer is the provider's public URL, without a trailing slash. It must match
	// the "iss" claim of every id_token this client accepts.
	Issuer string
	// ClientID and ClientSecret authenticate this caller at the token,
	// introspection and revocation endpoints.
	ClientID     string
	ClientSecret string
	// HTTP is the transport. Nil means a client with DefaultTimeout.
	HTTP *http.Client
	// AllowInsecureHTTP is only for loopback or an explicitly trusted local
	// transport. Public deployments must use HTTPS.
	AllowInsecureHTTP bool

	mu        sync.Mutex
	discovery *Discovery
	fetchedAt time.Time
	keys      *keySet
	// now is the clock, swappable in tests.
	now func() time.Time
}

// Discovery is the OpenID Connect discovery document. Unknown fields are
// ignored: the provider may grow capabilities this client does not use.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	// EndSessionEndpoint is the RP-Initiated Logout endpoint. Sending the
	// browser there is what ends the provider's own SSO session — clearing a
	// downstream service's own cookie does not, which is why a "logout" that
	// stops at the service leaves the next sign-in silently already-signed-in.
	EndSessionEndpoint               string   `json:"end_session_endpoint"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
	PromptValuesSupported            []string `json:"prompt_values_supported"`
	// The three *AuthMethodsSupported lists are separate because a provider may
	// accept different client authentication at each endpoint. Reading the
	// token endpoint's list and assuming the other two match is a guess that
	// fails only against a provider that differs — which is to say, later, and
	// somewhere the caller is not looking.
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
}

// TokenResponse is what the token endpoint returns.
type TokenResponse struct {
	// AccessToken is opaque. It is not a JWT — do not try to parse it. To learn
	// what it stands for, call UserInfo or Introspect.
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	// ExpiresIn is the access token's remaining lifetime in seconds.
	ExpiresIn int `json:"expires_in"`
	// RefreshToken is issued only when offline_access was granted.
	RefreshToken string `json:"refresh_token,omitempty"`
	// IDToken is a signed JWT. Pass it to VerifyIDToken; do not read its claims
	// without doing so.
	IDToken string `json:"id_token,omitempty"`
	// Scope is what was actually granted, which may be less than what was
	// requested. This, not the request, is what the caller got.
	Scope string `json:"scope"`
}

// Scopes splits the granted scope string.
func (t TokenResponse) Scopes() []string { return strings.Fields(t.Scope) }

// Expiry converts ExpiresIn into an absolute instant, measured from now.
func (t TokenResponse) Expiry(now time.Time) time.Time {
	return now.Add(time.Duration(t.ExpiresIn) * time.Second)
}

// UserInfo is the set of claims covered by an access token's scopes. Only
// Subject is guaranteed; a claim whose value is empty is absent rather than
// blank, so a zero field means "not granted or not set", never "granted as
// empty string".
type UserInfo struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Locale        string   `json:"locale,omitempty"`
	Roles         []string `json:"roles,omitempty"`
}

// HasRole reports whether the user holds role.
//
// Check the role your own service defines, not a provider-wide administrator
// role: holding one is not the same as being an administrator of your service,
// and treating it as such silently widens who can act.
func (u UserInfo) HasRole(role string) bool {
	for _, held := range u.Roles {
		if held == role {
			return true
		}
	}
	return false
}

// ValidateSubject prevents token substitution by requiring UserInfo to name
// the same subject as the already verified ID token from this login.
func (u UserInfo) ValidateSubject(id IDToken) error {
	if u.Subject == "" || id.Subject == "" || u.Subject != id.Subject {
		return errors.New("identity: userinfo sub does not match the verified id_token")
	}
	return nil
}

// Introspection is the token introspection result.
type Introspection struct {
	// Active is the field to read first. When false, every other field is
	// absent — an inactive token reveals nothing about itself.
	Active    bool   `json:"active"`
	Subject   string `json:"sub,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Expires   int64  `json:"exp,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// Error is an OAuth 2.0 error response (RFC 6749 §5.2).
//
// A conformant provider answers every credential failure at the token endpoint with
// invalid_grant, without distinguishing a missing code from an expired one or a
// mismatched code_verifier. That is deliberate on the provider's side, so this
// type cannot tell those apart either.
type Error struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	// Status is the HTTP status the error arrived with.
	Status int `json:"-"`
}

func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("identity: %s: %s", e.Code, e.Description)
	}
	if e.Code != "" {
		return "identity: " + e.Code
	}
	return fmt.Sprintf("identity: provider returned %d", e.Status)
}

// Common OAuth error codes.
const (
	ErrCodeInvalidGrant        = "invalid_grant"
	ErrCodeInvalidClient       = "invalid_client"
	ErrCodeInvalidToken        = "invalid_token"
	ErrCodeUnsupportedGrant    = "unsupported_grant_type"
	ErrCodeLoginRequired       = "login_required"
	ErrCodeInvalidRequest      = "invalid_request"
	ErrCodeInsufficientScope   = "insufficient_scope"
	ErrCodeUnauthorizedClient  = "unauthorized_client"
	ErrCodeAccessDenied        = "access_denied"
	ErrCodeServerError         = "server_error"
	ErrCodeTemporarilyUnavail  = "temporarily_unavailable"
	ErrCodeInteractionRequired = "interaction_required"
)

// Is reports whether err is an *Error with the given code.
func Is(err error, code string) bool {
	var oe *Error
	return errors.As(err, &oe) && oe.Code == code
}

func (c *Client) httpClient() *http.Client {
	base := c.HTTP
	if base == nil {
		base = &http.Client{Timeout: DefaultTimeout}
	}
	clone := *base
	if clone.CheckRedirect == nil {
		clone.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return &clone
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// Discover fetches (and caches) the provider's discovery document.
//
// Everything else in this package routes through it, which is what keeps
// endpoint paths out of callers. The document is re-fetched after discoveryTTL.
func (c *Client) Discover(ctx context.Context) (Discovery, error) {
	c.mu.Lock()
	if c.discovery != nil && c.clock().Sub(c.fetchedAt) < discoveryTTL {
		doc := *c.discovery
		c.mu.Unlock()
		return doc, nil
	}
	c.mu.Unlock()

	if c.Issuer == "" {
		return Discovery{}, errors.New("identity: Issuer is required")
	}
	issuerURL, err := url.Parse(strings.TrimRight(c.Issuer, "/"))
	if err != nil {
		return Discovery{}, fmt.Errorf("identity: invalid issuer: %w", err)
	}
	host := strings.ToLower(issuerURL.Hostname())
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if issuerURL.Scheme != "https" && !(issuerURL.Scheme == "http" && (loopback || c.AllowInsecureHTTP)) {
		return Discovery{}, errors.New("identity: non-loopback HTTP issuer is forbidden; use HTTPS")
	}
	target := issuerURL.String() + "/.well-known/openid-configuration"

	var doc Discovery
	if err := c.getJSON(ctx, target, "", &doc); err != nil {
		return Discovery{}, fmt.Errorf("identity: discovery: %w", err)
	}
	// A discovery document whose issuer is not the one we asked is either a
	// misconfiguration or somebody else's provider. Either way it must not
	// become the basis for verifying tokens.
	if doc.Issuer != strings.TrimRight(c.Issuer, "/") {
		return Discovery{}, fmt.Errorf(
			"identity: discovery issuer %q does not match configured issuer %q",
			doc.Issuer, c.Issuer)
	}
	if err := doc.checkOrigin(issuerURL); err != nil {
		return Discovery{}, err
	}

	c.mu.Lock()
	c.discovery = &doc
	c.fetchedAt = c.clock()
	c.mu.Unlock()
	return doc, nil
}

// checkOrigin requires every advertised endpoint to live on the issuer's own
// origin.
//
// The issuer match above only proves the document says the right name. A
// tampered document that keeps the issuer and moves token_endpoint elsewhere
// would send the client secret and the authorization code to that host, and
// nothing at the call site would look unusual — the login would simply work,
// somewhere else as well. This is the check the two hand-written clients this
// package replaced both had, and it is not one to lose on the way in.
func (d Discovery) checkOrigin(issuer *url.URL) error {
	for _, endpoint := range []struct{ field, raw string }{
		{"authorization_endpoint", d.AuthorizationEndpoint},
		{"token_endpoint", d.TokenEndpoint},
		{"userinfo_endpoint", d.UserInfoEndpoint},
		{"jwks_uri", d.JWKSURI},
		{"revocation_endpoint", d.RevocationEndpoint},
		{"introspection_endpoint", d.IntrospectionEndpoint},
		{"end_session_endpoint", d.EndSessionEndpoint},
	} {
		// An endpoint this provider does not advertise is not a violation; it
		// fails later, at the call that needed it, saying so.
		if endpoint.raw == "" {
			continue
		}
		target, err := url.Parse(endpoint.raw)
		if err != nil {
			return fmt.Errorf("identity: discovery %s %q is not a URL: %w", endpoint.field, endpoint.raw, err)
		}
		if !strings.EqualFold(target.Scheme, issuer.Scheme) ||
			!strings.EqualFold(target.Host, issuer.Host) ||
			target.User != nil || target.Fragment != "" {
			return fmt.Errorf("identity: discovery %s %q is not on the issuer's origin %q",
				endpoint.field, endpoint.raw, issuer.Scheme+"://"+issuer.Host)
		}
	}
	return nil
}

// AuthorizeParams are the inputs to AuthorizeURL.
type AuthorizeParams struct {
	// RedirectURI must match one the client registered, verbatim.
	RedirectURI string
	// Scopes to request. "openid" is added if absent.
	Scopes []string
	// State is returned unchanged in the callback; compare it to what you sent.
	// Required — it is what stands between your callback and a CSRF.
	State string
	// Challenge comes from a PKCE pair; keep the matching Verifier for Exchange.
	Challenge PKCE
	// Nonce is written into the id_token and checked by VerifyIDToken.
	Nonce string
	// Prompt is optional: "none" for a silent attempt, "consent" to force the
	// consent screen.
	Prompt string
}

// AuthorizeURL builds the URL to send a browser to in order to start a login.
//
// It does not perform a request; the caller redirects the user's browser and
// receives the code at RedirectURI.
func (c *Client) AuthorizeURL(ctx context.Context, p AuthorizeParams) (string, error) {
	if c.ClientID == "" {
		return "", errors.New("identity: ClientID is required")
	}
	if p.RedirectURI == "" {
		return "", errors.New("identity: RedirectURI is required")
	}
	if p.State == "" {
		// Without state the callback cannot tell its own redirect from one
		// somebody else caused, so this is not defaulted quietly.
		return "", errors.New("identity: State is required")
	}
	if p.Challenge.Challenge == "" {
		return "", errors.New("identity: Challenge is required (build one with NewPKCE)")
	}

	doc, err := c.Discover(ctx)
	if err != nil {
		return "", err
	}
	endpoint, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("identity: bad authorization endpoint %q: %w", doc.AuthorizationEndpoint, err)
	}

	scopes := p.Scopes
	if !contains(scopes, ScopeOpenID) {
		scopes = append([]string{ScopeOpenID}, scopes...)
	}

	q := endpoint.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", p.State)
	q.Set("code_challenge", p.Challenge.Challenge)
	q.Set("code_challenge_method", p.Challenge.Method)
	if p.Nonce != "" {
		q.Set("nonce", p.Nonce)
	}
	if p.Prompt != "" {
		q.Set("prompt", p.Prompt)
	}
	endpoint.RawQuery = q.Encode()
	return endpoint.String(), nil
}

// LogoutParams are the inputs to EndSessionURL.
type LogoutParams struct {
	// IDToken is a previously issued id_token, used as the hint that tells the
	// provider whose session to end and which client is asking. An expired one
	// still works as a hint; without any, the provider ends the session but has
	// no way to validate PostLogoutRedirectURI and so will not redirect.
	IDToken string
	// PostLogoutRedirectURI must match one this client registered, verbatim.
	PostLogoutRedirectURI string
	// State is appended to PostLogoutRedirectURI unchanged.
	State string
}

// EndSessionURL builds the URL to send a browser to in order to end the
// provider's session (OpenID Connect RP-Initiated Logout).
//
// Clearing your own session cookie is only half of a logout on a platform with
// shared sign-on: the provider's session outlives it, so the next sign-in
// succeeds silently and the user is not actually signed out anywhere. Send the
// browser here after clearing your own session.
//
// It returns an error when the provider's discovery document advertises no
// end_session_endpoint, rather than guessing a path — a guessed logout URL that
// 404s looks exactly like a logout that worked.
func (c *Client) EndSessionURL(ctx context.Context, p LogoutParams) (string, error) {
	doc, err := c.Discover(ctx)
	if err != nil {
		return "", err
	}
	if doc.EndSessionEndpoint == "" {
		return "", errors.New("identity: provider advertises no end_session_endpoint")
	}
	endpoint, err := url.Parse(doc.EndSessionEndpoint)
	if err != nil {
		return "", fmt.Errorf("identity: bad end session endpoint %q: %w", doc.EndSessionEndpoint, err)
	}
	q := endpoint.Query()
	if p.IDToken != "" {
		q.Set("id_token_hint", p.IDToken)
	}
	if p.PostLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", p.PostLogoutRedirectURI)
	}
	if p.State != "" {
		q.Set("state", p.State)
	}
	endpoint.RawQuery = q.Encode()
	return endpoint.String(), nil
}

// Exchange trades an authorization code for tokens.
//
// redirectURI must be the same one used to obtain the code, and verifier the
// one whose challenge was sent with it.
func (c *Client) Exchange(ctx context.Context, code, redirectURI, verifier string) (TokenResponse, error) {
	doc, err := c.Discover(ctx)
	if err != nil {
		return TokenResponse{}, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	var out TokenResponse
	err = c.postForm(ctx, doc.TokenEndpoint, form, true, &out)
	return out, err
}

// Refresh exchanges a refresh token for a fresh access token.
//
// A refresh token may be rotated: if the response carries a new one, store it
// and drop the old.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (TokenResponse, error) {
	doc, err := c.Discover(ctx)
	if err != nil {
		return TokenResponse{}, err
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	var out TokenResponse
	err = c.postForm(ctx, doc.TokenEndpoint, form, true, &out)
	return out, err
}

// UserInfo fetches the claims an access token covers.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (UserInfo, error) {
	var out UserInfo
	err := c.userInfo(ctx, accessToken, &out)
	return out, err
}

// UserInfoRaw is UserInfo without the typed struct, for callers that need
// claims a downstream service added and this package does not know about.
func (c *Client) UserInfoRaw(ctx context.Context, accessToken string) (map[string]any, error) {
	out := map[string]any{}
	err := c.userInfo(ctx, accessToken, &out)
	return out, err
}

func (c *Client) userInfo(ctx context.Context, accessToken string, out any) error {
	if accessToken == "" {
		return errors.New("identity: access token is required")
	}
	doc, err := c.Discover(ctx)
	if err != nil {
		return err
	}
	return c.getJSON(ctx, doc.UserInfoEndpoint, accessToken, out)
}

// Introspect asks whether a token is still valid.
//
// A token this client did not issue comes back inactive rather than as an
// error, so a false Active means "not valid for you" and nothing more.
func (c *Client) Introspect(ctx context.Context, token string) (Introspection, error) {
	doc, err := c.Discover(ctx)
	if err != nil {
		return Introspection{}, err
	}
	var out Introspection
	err = c.postForm(ctx, doc.IntrospectionEndpoint, url.Values{"token": {token}}, true, &out)
	return out, err
}

// Revoke invalidates an access or refresh token.
//
// Revoking a token that does not exist succeeds, per RFC 7009 — the endpoint is
// not an oracle for which tokens are real.
func (c *Client) Revoke(ctx context.Context, token string) error {
	doc, err := c.Discover(ctx)
	if err != nil {
		return err
	}
	return c.postForm(ctx, doc.RevocationEndpoint, url.Values{"token": {token}}, true, nil)
}

// getJSON performs a GET and decodes the response. bearer, when non-empty, is
// sent as an Authorization header.
func (c *Client) getJSON(ctx context.Context, target, bearer string, out any) error {
	if target == "" {
		return errors.New("identity: endpoint is not advertised by this provider")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.do(req, out)
}

// postForm performs a form POST. When authenticate is true the client's
// credentials are sent with HTTP Basic (client_secret_basic).
func (c *Client) postForm(ctx context.Context, target string, form url.Values, authenticate bool, out any) error {
	if target == "" {
		return errors.New("identity: endpoint is not advertised by this provider")
	}
	if authenticate && (c.ClientID == "" || c.ClientSecret == "") {
		return errors.New("identity: ClientID and ClientSecret are required for this endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if authenticate {
		// client_secret_basic keeps the secret out of the body, so it does not
		// end up in a request log that records post data.
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return fmt.Errorf("identity: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		oerr := &Error{Status: resp.StatusCode}
		// A non-JSON error body (a proxy's HTML page, say) leaves Code empty
		// rather than becoming a bogus code; Error() falls back to the status.
		_ = json.Unmarshal(body, oerr)
		return oerr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("identity: decode response: %w", err)
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

// b64 is the unpadded base64url encoding every JOSE field uses.
var b64 = base64.RawURLEncoding
