package graph

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/viant/afs"
	"golang.org/x/oauth2"
)

type AuthFlow string

const (
	AuthFlowDevice   AuthFlow = "device"
	AuthFlowAuthCode AuthFlow = "auth-code"
)

const defaultMicrosoftAuthority = "https://login.microsoftonline.com"

var errOAuthTokenMissing = errors.New("no usable OAuth token")

type ManagerConfig struct {
	ClientID           string
	StorageDir         string
	NamespaceClaimKeys []string
	AuthFlow           AuthFlow
	Authority          string

	OAuthRedirectURL      string
	OAuthScopes           []string
	OAuthHTTPClient       *http.Client
	OAuthAuthURLOverride  string
	OAuthTokenURLOverride string
}

type oauthTokenRecord struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	TokenType    string    `json:"tokenType,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
}

type oauthCodeCredential struct {
	m        *Manager
	ns       string
	alias    string
	tenantID string
	scopes   []string
}

func NormalizeAuthFlow(value string) AuthFlow {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(AuthFlowDevice):
		return AuthFlowDevice
	case string(AuthFlowAuthCode), "authcode", "authorization-code", "authorization_code", "oauth-code", "oauth_code":
		return AuthFlowAuthCode
	default:
		return AuthFlow(value)
	}
}

func ValidAuthFlow(value string) bool {
	flow := NormalizeAuthFlow(value)
	return flow == AuthFlowDevice || flow == AuthFlowAuthCode
}

func DefaultOAuthScopes() []string {
	return []string{
		"openid",
		"profile",
		"offline_access",
		"User.Read",
		"Mail.Read",
		"Mail.Send",
		"Mail.ReadWrite",
		"Calendars.ReadWrite",
		"Tasks.ReadWrite",
	}
}

func ParseScopes(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t'
	})
	return normalizeScopes(parts)
}

func normalizeScopes(scopes []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		key := strings.ToLower(scope)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, scope)
	}
	return out
}

func normalizedScopeKey(scopes []string) string {
	norm := make([]string, 0, len(scopes))
	for _, scope := range normalizeScopes(scopes) {
		norm = append(norm, strings.ToLower(scope))
	}
	sort.Strings(norm)
	return strings.Join(norm, " ")
}

func scopesHash(scopes []string) string {
	sum := sha256.Sum256([]byte(normalizedScopeKey(scopes)))
	return hex.EncodeToString(sum[:])[:16]
}

func (m *Manager) effectiveOAuthScopes(scopes []string) []string {
	if len(normalizeScopes(scopes)) > 0 {
		return normalizeScopes(scopes)
	}
	if len(m.oauthScopes) > 0 {
		return append([]string(nil), m.oauthScopes...)
	}
	return DefaultOAuthScopes()
}

func (m *Manager) oauthTokenURL(ns, alias, tenantID string, scopes []string) string {
	base := m.oauthTokenBaseURL()
	name := fmt.Sprintf("%s_%s_%s_%s_%s_oauth_token.json",
		safePart(ns),
		safePart(alias),
		safePart(tenantID),
		safePart(m.clientID),
		scopesHash(scopes),
	)
	if strings.HasPrefix(base, "mem://") || strings.HasPrefix(base, "file://") {
		return base + "/" + name
	}
	return filepath.Join(base, name)
}

func (m *Manager) oauthTokenBaseURL() string {
	return strings.TrimRight(os.ExpandEnv(m.storageDir), "/")
}

func (m *Manager) oauthTokenPrefix(ns, alias, tenantID string) string {
	return fmt.Sprintf("%s_%s_%s_%s_",
		safePart(ns),
		safePart(alias),
		safePart(tenantID),
		safePart(m.clientID),
	)
}

func (m *Manager) clearOAuthTokens(ctx context.Context, ns, alias, tenantID string, scopes []string) (bool, []string, error) {
	base := m.oauthTokenBaseURL()
	prefix := m.oauthTokenPrefix(ns, alias, tenantID)
	objects, err := afs.New().List(ctx, base)
	if err != nil {
		cleared, err := m.clearOAuthTokenForScopes(ctx, ns, alias, tenantID, scopes)
		if err != nil {
			return cleared, nil, err
		}
		return cleared, []string{fmt.Sprintf("failed to list OAuth token storage; only current-scope token was checked: %v", err)}, nil
	}
	cleared := false
	for _, object := range objects {
		if object == nil || object.IsDir() {
			continue
		}
		name := object.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, "_oauth_token.json") {
			continue
		}
		if err := afs.New().Delete(ctx, object.URL()); err != nil {
			return cleared, nil, err
		}
		cleared = true
	}
	return cleared, nil, nil
}

func (m *Manager) clearOAuthTokenForScopes(ctx context.Context, ns, alias, tenantID string, scopes []string) (bool, error) {
	oauthURL := m.oauthTokenURL(ns, alias, tenantID, scopes)
	oauthExists, _ := afs.New().Exists(ctx, oauthURL)
	if !oauthExists {
		return false, nil
	}
	if err := afs.New().Delete(ctx, oauthURL); err != nil {
		return false, err
	}
	return true, nil
}

func (m *Manager) oauthEndpoint(tenantID string) oauth2.Endpoint {
	if m.oauthAuthURLOverride != "" || m.oauthTokenURLOverride != "" {
		return oauth2.Endpoint{AuthURL: m.oauthAuthURLOverride, TokenURL: m.oauthTokenURLOverride}
	}
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		tenantID = "common"
	}
	authority := strings.TrimRight(strings.TrimSpace(m.authority), "/")
	if authority == "" {
		authority = defaultMicrosoftAuthority
	}
	base := authority + "/" + tenantID + "/oauth2/v2.0"
	return oauth2.Endpoint{
		AuthURL:  base + "/authorize",
		TokenURL: base + "/token",
	}
}

func (m *Manager) oauthConfig(tenantID string, scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:    m.clientID,
		Endpoint:    m.oauthEndpoint(tenantID),
		RedirectURL: m.oauthRedirectURL,
		Scopes:      m.effectiveOAuthScopes(scopes),
	}
}

func (m *Manager) oauthContext(ctx context.Context) context.Context {
	if m.oauthHTTPClient == nil {
		return ctx
	}
	return context.WithValue(ctx, oauth2.HTTPClient, m.oauthHTTPClient)
}

func (m *Manager) AuthCodeURL(tenantID string, scopes []string, state, verifier string) string {
	return m.oauthConfig(tenantID, scopes).AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("prompt", "select_account"),
	)
}

func (m *Manager) ExchangeAuthCode(ctx context.Context, ns, alias, tenantID string, scopes []string, code, verifier string) error {
	if err := m.ensureDirs(); err != nil {
		return err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.New("authorization code is required")
	}
	verifier = strings.TrimSpace(verifier)
	if verifier == "" {
		return errors.New("PKCE verifier is required")
	}
	scopes = m.effectiveOAuthScopes(scopes)
	tok, err := m.oauthConfig(tenantID, scopes).Exchange(m.oauthContext(ctx), code, oauth2.VerifierOption(verifier))
	if err != nil {
		if IsTransientAuthProviderError(err) {
			return NewTransientAuthProviderError(err)
		}
		return err
	}
	if tok == nil || tok.AccessToken == "" {
		return errors.New("OAuth token exchange returned no access token")
	}
	return m.saveOAuthToken(ctx, ns, alias, tenantID, scopes, tok)
}

func (m *Manager) oauthCredential(ctx context.Context, ns, alias, tenantID string, scopes []string) (azcore.TokenCredential, error) {
	scopes = m.effectiveOAuthScopes(scopes)
	if _, err := m.oauthToken(ctx, ns, alias, tenantID, scopes); err != nil {
		return nil, err
	}
	return &oauthCodeCredential{m: m, ns: ns, alias: alias, tenantID: tenantID, scopes: scopes}, nil
}

func (c *oauthCodeCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = c.scopes
	}
	tok, err := c.m.oauthToken(ctx, c.ns, c.alias, c.tenantID, scopes)
	if err != nil {
		return azcore.AccessToken{}, err
	}
	return azcore.AccessToken{Token: tok.AccessToken, ExpiresOn: tok.Expiry}, nil
}

func (m *Manager) oauthAuthCheck(ctx context.Context, alias, tenantID string, scopes []string) AuthCheckResult {
	start := time.Now()
	debugf("graph.oauthAuthCheck start alias=%q tenant=%q deadline_in=%s", alias, tenantID, debugDeadline(ctx))
	if err := m.ensureDirs(); err != nil {
		return AuthCheckResult{Status: AuthCheckFailed, Reason: "storage_unavailable", Err: err}
	}
	dsc, _ := m.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	scopes = m.effectiveOAuthScopes(scopes)
	_, err := m.oauthToken(ctx, ns, alias, tenantID, scopes)
	debugf("graph.oauthAuthCheck token ns=%q alias=%q tenant=%q err=%v elapsed=%s", ns, alias, tenantID, err, time.Since(start).Round(time.Millisecond))
	if err == nil {
		return AuthCheckResult{Status: AuthCheckReady}
	}
	if errors.Is(err, errOAuthTokenMissing) {
		return AuthCheckResult{Status: AuthCheckNeedsInteractive, Reason: "no_usable_oauth_token"}
	}
	if IsTransientAuthProviderError(err) {
		return AuthCheckResult{Status: AuthCheckTransient, Reason: "transient_provider", Err: NewTransientAuthProviderError(err)}
	}
	return AuthCheckResult{Status: AuthCheckNeedsInteractive, Reason: "oauth_token_failed", Err: err}
}

func (m *Manager) oauthToken(ctx context.Context, ns, alias, tenantID string, scopes []string) (*oauth2.Token, error) {
	rec, err := m.loadOAuthToken(ctx, ns, alias, tenantID, scopes)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, errOAuthTokenMissing
	}
	scopes = m.effectiveOAuthScopes(scopes)
	startToken := rec.oauth2Token()
	tctx, cancel := context.WithTimeout(m.oauthContext(ctx), silentTokenTimeout)
	defer cancel()
	tok, err := m.oauthConfig(tenantID, scopes).TokenSource(tctx, startToken).Token()
	if err != nil {
		if IsTransientAuthProviderError(err) {
			return nil, NewTransientAuthProviderError(err)
		}
		return nil, err
	}
	if tok == nil || tok.AccessToken == "" {
		return nil, errors.New("OAuth token source returned no access token")
	}
	if !sameOAuthToken(startToken, tok) {
		if err := m.saveOAuthToken(ctx, ns, alias, tenantID, scopes, tok); err != nil {
			return nil, err
		}
	}
	return tok, nil
}

func (m *Manager) loadOAuthToken(ctx context.Context, ns, alias, tenantID string, scopes []string) (*oauthTokenRecord, error) {
	rc, err := afs.New().OpenURL(ctx, m.oauthTokenURL(ns, alias, tenantID, scopes))
	if err != nil || rc == nil {
		return nil, nil
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	var rec oauthTokenRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	if rec.AccessToken == "" && rec.RefreshToken == "" {
		return nil, errOAuthTokenMissing
	}
	return &rec, nil
}

func (m *Manager) saveOAuthToken(ctx context.Context, ns, alias, tenantID string, scopes []string, tok *oauth2.Token) error {
	rec := oauthTokenRecordFromToken(tok, scopes)
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return afs.New().Upload(ctx, m.oauthTokenURL(ns, alias, tenantID, scopes), 0o600, bytes.NewReader(data))
}

func oauthTokenRecordFromToken(tok *oauth2.Token, scopes []string) *oauthTokenRecord {
	if tok == nil {
		return &oauthTokenRecord{Scopes: normalizeScopes(scopes)}
	}
	return &oauthTokenRecord{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		TokenType:    tok.TokenType,
		Expiry:       tok.Expiry,
		Scopes:       normalizeScopes(scopes),
	}
}

func (r *oauthTokenRecord) oauth2Token() *oauth2.Token {
	if r == nil {
		return nil
	}
	return &oauth2.Token{
		AccessToken:  r.AccessToken,
		RefreshToken: r.RefreshToken,
		TokenType:    r.TokenType,
		Expiry:       r.Expiry,
	}
}

func sameOAuthToken(a, b *oauth2.Token) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.AccessToken == b.AccessToken &&
		a.RefreshToken == b.RefreshToken &&
		a.TokenType == b.TokenType &&
		a.Expiry.Equal(b.Expiry)
}
