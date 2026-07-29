package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultHTTPTimeout       = 10 * time.Second
	defaultKeyRefresh        = 15 * time.Minute
	minFailedRefreshInterval = time.Minute
	minUnknownKeyRefresh     = time.Minute
	maxMetadataResponse      = 1 << 20
)

// TokenVerifier validates a bearer token and returns only verified claims.
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (map[string]any, error)
}

// OIDCConfig contains trusted OAuth client data and optional discovery
// overrides used to validate MCP caller ID tokens.
type OIDCConfig struct {
	AuthURL    string
	TokenURL   string
	Issuer     string
	JWKSURL    string
	Audience   string
	Algorithms []string
	HTTPClient *http.Client
}

// OIDCVerifier validates signatures and the standard issuer, audience, expiry,
// and not-before claims using an OIDC provider's JWKS.
type OIDCVerifier struct {
	issuer     string
	jwksURL    string
	audience   string
	algorithms []string
	client     *http.Client

	refreshMu    sync.Mutex
	lastStaleTry time.Time
	lastMissTry  time.Time

	keysMu      sync.RWMutex
	keys        map[string]*rsa.PublicKey
	lastRefresh time.Time
}

type discoveryDocument struct {
	Issuer     string   `json:"issuer"`
	JWKSURL    string   `json:"jwks_uri"`
	Algorithms []string `json:"id_token_signing_alg_values_supported"`
}

type jwksDocument struct {
	Keys []jwkDocument `json:"keys"`
}

type jwkDocument struct {
	KeyType  string   `json:"kty"`
	KeyID    string   `json:"kid"`
	Use      string   `json:"use"`
	KeyOps   []string `json:"key_ops"`
	Alg      string   `json:"alg"`
	Modulus  string   `json:"n"`
	Exponent string   `json:"e"`
}

// NewOIDCVerifier discovers missing provider metadata, fetches the initial
// signing keys, and returns a strict verifier. Startup fails closed when the
// trusted issuer, JWKS URL, or audience cannot be established.
func NewOIDCVerifier(ctx context.Context, cfg OIDCConfig) (*OIDCVerifier, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg.AuthURL = strings.TrimSpace(cfg.AuthURL)
	cfg.TokenURL = strings.TrimSpace(cfg.TokenURL)
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.JWKSURL = strings.TrimSpace(cfg.JWKSURL)
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	cfg.Algorithms = normalizeAlgorithms(cfg.Algorithms)
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{jwt.SigningMethodRS256.Alg()}
	}
	if err := validateAlgorithms(cfg.Algorithms); err != nil {
		return nil, err
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("OIDC audience is required")
	}
	for name, value := range map[string]string{
		"authorization endpoint": cfg.AuthURL,
		"token endpoint":         cfg.TokenURL,
	} {
		if value != "" {
			if err := validateTrustedURL(value); err != nil {
				return nil, fmt.Errorf("invalid OIDC %s: %w", name, err)
			}
		}
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	if cfg.Issuer == "" || cfg.JWKSURL == "" {
		document, err := discover(ctx, client, cfg.AuthURL, cfg.TokenURL)
		if err != nil {
			return nil, err
		}
		discoveredIssuer := strings.TrimSpace(document.Issuer)
		if cfg.Issuer != "" && discoveredIssuer != cfg.Issuer {
			return nil, fmt.Errorf("OIDC discovery issuer %q does not match configured issuer %q", discoveredIssuer, cfg.Issuer)
		}
		if cfg.Issuer == "" {
			cfg.Issuer = discoveredIssuer
		}
		if cfg.JWKSURL == "" {
			cfg.JWKSURL = strings.TrimSpace(document.JWKSURL)
		}
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("OIDC issuer is required (discovery did not provide it)")
	}
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("OIDC JWKS URL is required (discovery did not provide it)")
	}
	if err := validateIssuerURL(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("invalid OIDC issuer: %w", err)
	}
	if err := validateTrustedURL(cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("invalid OIDC JWKS URL: %w", err)
	}

	result := &OIDCVerifier{
		issuer:     cfg.Issuer,
		jwksURL:    cfg.JWKSURL,
		audience:   cfg.Audience,
		algorithms: append([]string(nil), cfg.Algorithms...),
		client:     client,
		keys:       map[string]*rsa.PublicKey{},
	}
	if err := result.refreshKeys(ctx); err != nil {
		return nil, fmt.Errorf("load OIDC signing keys: %w", err)
	}
	return result, nil
}

// Verify returns claims only after the token signature and standard OIDC
// constraints have all been validated.
func (v *OIDCVerifier) Verify(ctx context.Context, rawToken string) (map[string]any, error) {
	if v == nil {
		return nil, fmt.Errorf("OIDC verifier is not configured")
	}
	rawToken = normalizeBearer(rawToken)
	if rawToken == "" {
		return nil, fmt.Errorf("bearer token is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := v.refreshIfStale(ctx); err != nil && !v.hasKeys() {
		return nil, fmt.Errorf("refresh OIDC signing keys: %w", err)
	}

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			keyID, _ := token.Header["kid"].(string)
			if strings.TrimSpace(keyID) == "" {
				return nil, fmt.Errorf("JWT kid header is required")
			}
			if key := v.lookupKey(keyID); key != nil {
				return key, nil
			}
			if err := v.refreshUnknownKey(ctx, keyID); err != nil {
				return nil, fmt.Errorf("refresh OIDC signing keys: %w", err)
			}
			if key := v.lookupKey(keyID); key != nil {
				return key, nil
			}
			return nil, fmt.Errorf("JWT signing key was not found")
		},
		jwt.WithValidMethods(v.algorithms),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid bearer token: %w", err)
	}
	if token == nil || !token.Valid {
		return nil, fmt.Errorf("invalid bearer token")
	}
	if err := validateIDTokenClaims(claims, v.audience); err != nil {
		return nil, fmt.Errorf("invalid bearer token: %w", err)
	}
	result := make(map[string]any, len(claims))
	for key, value := range claims {
		result[key] = value
	}
	return result, nil
}

func (v *OIDCVerifier) refreshIfStale(ctx context.Context) error {
	v.keysMu.RLock()
	stale := time.Since(v.lastRefresh) >= defaultKeyRefresh
	v.keysMu.RUnlock()
	if !stale {
		return nil
	}
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	v.keysMu.RLock()
	stale = time.Since(v.lastRefresh) >= defaultKeyRefresh
	v.keysMu.RUnlock()
	if !stale {
		return nil
	}
	now := time.Now()
	if !v.lastStaleTry.IsZero() && now.Sub(v.lastStaleTry) < minFailedRefreshInterval {
		return nil
	}
	v.lastStaleTry = now
	return v.loadKeys(ctx)
}

func (v *OIDCVerifier) refreshKeys(ctx context.Context) error {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	return v.loadKeys(ctx)
}

func (v *OIDCVerifier) refreshUnknownKey(ctx context.Context, keyID string) error {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	if v.lookupKey(keyID) != nil {
		return nil
	}
	now := time.Now()
	if !v.lastMissTry.IsZero() && now.Sub(v.lastMissTry) < minUnknownKeyRefresh {
		return nil
	}
	v.lastMissTry = now
	return v.loadKeys(ctx)
}

func (v *OIDCVerifier) loadKeys(ctx context.Context) error {
	var document jwksDocument
	if err := fetchJSON(ctx, v.client, v.jwksURL, &document); err != nil {
		return err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, item := range document.Keys {
		if item.KeyType != "RSA" || strings.TrimSpace(item.KeyID) == "" {
			continue
		}
		if item.Use != "" && item.Use != "sig" {
			continue
		}
		if len(item.KeyOps) > 0 && !contains(item.KeyOps, "verify") {
			continue
		}
		if item.Alg != "" && !contains(v.algorithms, item.Alg) {
			continue
		}
		publicKey, err := rsaPublicKey(item)
		if err != nil {
			continue
		}
		keys[item.KeyID] = publicKey
	}
	if len(keys) == 0 {
		return fmt.Errorf("OIDC JWKS contains no usable RSA signing keys")
	}
	v.keysMu.Lock()
	v.keys = keys
	v.lastRefresh = time.Now()
	v.keysMu.Unlock()
	return nil
}

func (v *OIDCVerifier) lookupKey(keyID string) *rsa.PublicKey {
	v.keysMu.RLock()
	defer v.keysMu.RUnlock()
	return v.keys[keyID]
}

func (v *OIDCVerifier) hasKeys() bool {
	v.keysMu.RLock()
	defer v.keysMu.RUnlock()
	return len(v.keys) > 0
}

func discover(ctx context.Context, client *http.Client, authURL, tokenURL string) (*discoveryDocument, error) {
	candidates := discoveryCandidates(authURL, tokenURL)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("cannot derive OIDC discovery URL from OAuth endpoints")
	}
	var failures []string
	for _, candidate := range candidates {
		if err := validateTrustedURL(candidate); err != nil {
			failures = append(failures, err.Error())
			continue
		}
		var document discoveryDocument
		if err := fetchJSON(ctx, client, candidate, &document); err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if strings.TrimSpace(document.Issuer) == "" || strings.TrimSpace(document.JWKSURL) == "" {
			failures = append(failures, candidate+" is missing issuer or jwks_uri")
			continue
		}
		if err := validateIssuerURL(document.Issuer); err != nil {
			failures = append(failures, candidate+" returned an invalid issuer: "+err.Error())
			continue
		}
		if err := validateURLTransition(candidate, document.Issuer); err != nil {
			failures = append(failures, candidate+" returned an untrusted issuer: "+err.Error())
			continue
		}
		if err := validateURLTransition(candidate, document.JWKSURL); err != nil {
			failures = append(failures, candidate+" returned an untrusted jwks_uri: "+err.Error())
			continue
		}
		return &document, nil
	}
	return nil, fmt.Errorf("OIDC discovery failed: %s", strings.Join(failures, "; "))
}

func discoveryCandidates(values ...string) []string {
	seen := map[string]bool{}
	var result []string
	appendCandidate := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		result = append(result, value)
	}
	appendIssuerCandidates := func(parsed *url.URL, issuerPath string) {
		issuerPath = "/" + strings.Trim(strings.TrimSpace(issuerPath), "/")
		if issuerPath == "/" {
			issuerPath = ""
		}
		base := url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
		oidc := base
		oidc.Path = path.Join(issuerPath, "/.well-known/openid-configuration")
		appendCandidate(oidc.String())

		oauth := base
		oauth.Path = path.Join("/.well-known/oauth-authorization-server", issuerPath)
		appendCandidate(oauth.String())
	}
	for _, value := range values {
		parsed, err := url.Parse(strings.TrimSpace(value))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		segments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		for i := 0; i+1 < len(segments); i++ {
			switch segments[i] {
			case "oauth2":
				issuerSegments := append([]string(nil), segments[:i+2]...)
				if segments[i+1] == "v2.0" {
					issuerSegments = append(append([]string(nil), segments[:i]...), "v2.0")
				}
				appendIssuerCandidates(parsed, strings.Join(issuerSegments, "/"))
			case "realms":
				appendIssuerCandidates(parsed, strings.Join(segments[:i+2], "/"))
			}
		}
		appendIssuerCandidates(parsed, "")
	}
	return result
}

func fetchJSON(ctx context.Context, client *http.Client, endpoint string, target any) error {
	if err := validateTrustedURL(endpoint); err != nil {
		return fmt.Errorf("invalid metadata URL %q: %w", endpoint, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	safeClient := *client
	checkRedirect := safeClient.CheckRedirect
	safeClient.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) > 0 {
			if err := validateURLTransition(via[len(via)-1].URL.String(), request.URL.String()); err != nil {
				return err
			}
		}
		if checkRedirect != nil {
			return checkRedirect(request, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	response, err := safeClient.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", endpoint, err)
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL == nil {
		return fmt.Errorf("%s returned a response without a final URL", endpoint)
	}
	if err := validateURLTransition(endpoint, response.Request.URL.String()); err != nil {
		return fmt.Errorf("%s redirected to an untrusted origin: %w", endpoint, err)
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("%s returned status %d", endpoint, response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxMetadataResponse+1))
	if err != nil {
		return fmt.Errorf("%s response read failed: %w", endpoint, err)
	}
	if len(data) > maxMetadataResponse {
		return fmt.Errorf("%s response exceeds the %d byte limit", endpoint, maxMetadataResponse)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s returned invalid JSON: %w", endpoint, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("%s returned multiple JSON values", endpoint)
		}
		return fmt.Errorf("%s returned invalid trailing JSON: %w", endpoint, err)
	}
	return nil
}

func validateIDTokenClaims(claims jwt.MapClaims, audience string) error {
	subject, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(subject) == "" {
		return fmt.Errorf("OIDC subject is required")
	}
	if issuedAt, err := claims.GetIssuedAt(); err != nil {
		return fmt.Errorf("OIDC issued-at claim is invalid: %w", err)
	} else if issuedAt == nil {
		return fmt.Errorf("OIDC issued-at claim is required")
	}
	audiences, err := claims.GetAudience()
	if err != nil {
		return fmt.Errorf("OIDC audience claim is invalid: %w", err)
	}
	authorizedParty, hasAuthorizedParty := claims["azp"]
	if len(audiences) > 1 && !hasAuthorizedParty {
		return fmt.Errorf("OIDC authorized party is required for multiple audiences")
	}
	if hasAuthorizedParty {
		value, ok := authorizedParty.(string)
		if !ok || value != audience {
			return fmt.Errorf("OIDC authorized party does not match the expected audience")
		}
	}
	return nil
}

func rsaPublicKey(document jwkDocument) (*rsa.PublicKey, error) {
	modulus, err := base64.RawURLEncoding.DecodeString(document.Modulus)
	if err != nil || len(modulus) == 0 {
		return nil, fmt.Errorf("invalid RSA modulus")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(document.Exponent)
	if err != nil || len(exponentBytes) == 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	exponentValue := new(big.Int).SetBytes(exponentBytes)
	if !exponentValue.IsInt64() {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	exponent := exponentValue.Int64()
	if exponent < 3 || exponent > int64(^uint(0)>>1) || exponent%2 == 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(exponent)}
	if publicKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA signing key must be at least 2048 bits")
	}
	return publicKey, nil
}

func normalizeAlgorithms(values []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	return result
}

func validateAlgorithms(values []string) error {
	supported := map[string]bool{
		jwt.SigningMethodRS256.Alg(): true,
		jwt.SigningMethodRS384.Alg(): true,
		jwt.SigningMethodRS512.Alg(): true,
		jwt.SigningMethodPS256.Alg(): true,
		jwt.SigningMethodPS384.Alg(): true,
		jwt.SigningMethodPS512.Alg(): true,
	}
	for _, value := range values {
		if !supported[value] {
			return fmt.Errorf("unsupported OIDC signing algorithm %q", value)
		}
	}
	return nil
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func normalizeBearer(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= len("Bearer ") && strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return strings.TrimSpace(value[len("Bearer "):])
	}
	return value
}

func validateTrustedURL(value string) error {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return err
	}
	if parsed.Host == "" {
		return fmt.Errorf("URL host is required")
	}
	if parsed.User != nil {
		return fmt.Errorf("URL user information is not allowed")
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("URL fragment is not allowed")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	if parsed.Scheme == "http" && (strings.EqualFold(host, "localhost") || isLoopback(host)) {
		return nil
	}
	return fmt.Errorf("URL must use HTTPS (HTTP is allowed only for loopback testing)")
}

func validateIssuerURL(value string) error {
	if err := validateTrustedURL(value); err != nil {
		return err
	}
	parsed, _ := url.Parse(strings.TrimSpace(value))
	if parsed.RawQuery != "" {
		return fmt.Errorf("issuer URL query is not allowed")
	}
	return nil
}

func validateURLTransition(source, target string) error {
	if err := validateTrustedURL(source); err != nil {
		return err
	}
	if err := validateTrustedURL(target); err != nil {
		return err
	}
	sourceScheme, sourceHost, sourcePort, err := normalizedOrigin(source)
	if err != nil {
		return err
	}
	targetScheme, targetHost, targetPort, err := normalizedOrigin(target)
	if err != nil {
		return err
	}
	if sourceScheme != targetScheme || sourceHost != targetHost || sourcePort != targetPort {
		return fmt.Errorf("URL must not transition across origins")
	}
	return nil
}

func normalizedOrigin(value string) (scheme, host, port string, err error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return "", "", "", err
	}
	scheme = strings.ToLower(parsed.Scheme)
	host = strings.ToLower(parsed.Hostname())
	port = parsed.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme, host, port, nil
}

func isLoopback(host string) bool {
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
