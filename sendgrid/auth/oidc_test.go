package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestOIDCVerifierRejectsUntrustedTokens(t *testing.T) {
	privateKey := newTestRSAKey(t)
	otherKey := newTestRSAKey(t)
	const keyID = "test-key"
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, response, map[string]any{
				"issuer":   server.URL,
				"jwks_uri": server.URL + "/jwks",
			})
		case "/jwks":
			writeJSON(t, response, map[string]any{
				"keys": []any{testJWK(keyID, &privateKey.PublicKey)},
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	verifier, err := NewOIDCVerifier(context.Background(), OIDCConfig{
		AuthURL:  server.URL + "/authorize",
		Audience: "sendgrid-mcp-client",
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier failed: %v", err)
	}

	now := time.Now()
	baseClaims := jwt.MapClaims{
		"iss":   server.URL,
		"aud":   "sendgrid-mcp-client",
		"exp":   now.Add(time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"sub":   "alice-subject",
		"email": "alice@example.com",
	}
	validToken := signTestToken(t, privateKey, keyID, baseClaims)
	claims, err := verifier.Verify(context.Background(), validToken)
	if err != nil {
		t.Fatalf("valid token was rejected: %v", err)
	}
	if claims["sub"] != "alice-subject" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	multipleAudienceClaims := cloneMap(baseClaims, "aud", []string{"sendgrid-mcp-client", "other-audience"})
	multipleAudienceClaims["azp"] = "sendgrid-mcp-client"
	if _, err := verifier.Verify(context.Background(), signTestToken(t, privateKey, keyID, multipleAudienceClaims)); err != nil {
		t.Fatalf("valid multiple-audience token was rejected: %v", err)
	}

	testCases := []struct {
		name  string
		token func() string
	}{
		{
			name: "alg none",
			token: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodNone, baseClaims)
				token.Header["kid"] = keyID
				value, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
				if err != nil {
					t.Fatalf("sign none token: %v", err)
				}
				return value
			},
		},
		{
			name:  "wrong signature",
			token: func() string { return signTestToken(t, otherKey, keyID, baseClaims) },
		},
		{
			name: "wrong issuer",
			token: func() string {
				return signTestToken(t, privateKey, keyID, cloneMap(baseClaims, "iss", "https://attacker.example"))
			},
		},
		{
			name: "wrong audience",
			token: func() string {
				return signTestToken(t, privateKey, keyID, cloneMap(baseClaims, "aud", "other-client"))
			},
		},
		{
			name: "expired",
			token: func() string {
				return signTestToken(t, privateKey, keyID, cloneMap(baseClaims, "exp", now.Add(-time.Minute).Unix()))
			},
		},
		{
			name: "future not-before",
			token: func() string {
				return signTestToken(t, privateKey, keyID, cloneMap(baseClaims, "nbf", now.Add(time.Minute).Unix()))
			},
		},
		{
			name: "future issued-at",
			token: func() string {
				return signTestToken(t, privateKey, keyID, cloneMap(baseClaims, "iat", now.Add(time.Minute).Unix()))
			},
		},
		{
			name: "missing expiration",
			token: func() string {
				claims := cloneMap(baseClaims, "", nil)
				delete(claims, "exp")
				return signTestToken(t, privateKey, keyID, claims)
			},
		},
		{
			name: "missing issued-at",
			token: func() string {
				claims := cloneMap(baseClaims, "", nil)
				delete(claims, "iat")
				return signTestToken(t, privateKey, keyID, claims)
			},
		},
		{
			name: "missing subject",
			token: func() string {
				claims := cloneMap(baseClaims, "", nil)
				delete(claims, "sub")
				return signTestToken(t, privateKey, keyID, claims)
			},
		},
		{
			name: "multiple audiences without authorized party",
			token: func() string {
				return signTestToken(t, privateKey, keyID, cloneMap(baseClaims, "aud", []string{"sendgrid-mcp-client", "other-audience"}))
			},
		},
		{
			name: "wrong authorized party",
			token: func() string {
				return signTestToken(t, privateKey, keyID, cloneMap(baseClaims, "azp", "other-client"))
			},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := verifier.Verify(context.Background(), testCase.token()); err == nil {
				t.Fatal("expected token rejection")
			}
		})
	}
}

func TestOIDCDiscoveryBindsConfiguredIssuer(t *testing.T) {
	privateKey := newTestRSAKey(t)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(t, response, map[string]any{
				"issuer":   server.URL + "/different",
				"jwks_uri": server.URL + "/jwks",
			})
		case "/jwks":
			writeJSON(t, response, map[string]any{
				"keys": []any{testJWK("test-key", &privateKey.PublicKey)},
			})
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	_, err := NewOIDCVerifier(context.Background(), OIDCConfig{
		AuthURL:  server.URL + "/authorize",
		Issuer:   server.URL,
		Audience: "sendgrid-mcp-client",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match configured issuer") {
		t.Fatalf("NewOIDCVerifier error = %v, want discovery issuer mismatch", err)
	}
}

func TestOIDCDiscoveryRejectsCrossHostJWKSURI(t *testing.T) {
	privateKey := newTestRSAKey(t)
	var jwksRequests atomic.Int32
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		jwksRequests.Add(1)
		writeJSON(t, response, map[string]any{
			"keys": []any{testJWK("test-key", &privateKey.PublicKey)},
		})
	}))
	defer jwksServer.Close()

	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(t, response, map[string]any{
			"issuer":   discoveryServer.URL,
			"jwks_uri": testURLWithHostname(t, jwksServer.URL+"/jwks", "localhost"),
		})
	}))
	defer discoveryServer.Close()

	_, err := NewOIDCVerifier(context.Background(), OIDCConfig{
		AuthURL:    discoveryServer.URL + "/authorize",
		Audience:   "sendgrid-mcp-client",
		HTTPClient: discoveryServer.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "untrusted jwks_uri") {
		t.Fatalf("NewOIDCVerifier error = %v, want cross-host jwks_uri rejection", err)
	}
	if got := jwksRequests.Load(); got != 0 {
		t.Fatalf("cross-host JWKS endpoint received %d requests, want 0", got)
	}
}

func TestOIDCVerifierTreatsExplicitIssuerAndJWKSAsTrustAnchors(t *testing.T) {
	privateKey := newTestRSAKey(t)
	jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		writeJSON(t, response, map[string]any{
			"keys": []any{testJWK("test-key", &privateKey.PublicKey)},
		})
	}))
	defer jwksServer.Close()

	_, err := NewOIDCVerifier(context.Background(), OIDCConfig{
		AuthURL:    "https://oauth.example/authorize",
		TokenURL:   "https://oauth.example/token",
		Issuer:     "https://issuer.example",
		JWKSURL:    jwksServer.URL + "/jwks",
		Audience:   "sendgrid-mcp-client",
		HTTPClient: jwksServer.Client(),
	})
	if err != nil {
		t.Fatalf("explicit issuer and JWKS trust anchors were rejected: %v", err)
	}
}

func TestOIDCVerifierRejectsInsecureConfiguredOAuthEndpoints(t *testing.T) {
	_, err := NewOIDCVerifier(context.Background(), OIDCConfig{
		AuthURL:  "http://identity.example/authorize",
		Issuer:   "https://identity.example",
		JWKSURL:  "https://identity.example/jwks",
		Audience: "sendgrid-mcp-client",
	})
	if err == nil || !strings.Contains(err.Error(), "authorization endpoint") {
		t.Fatalf("NewOIDCVerifier error = %v, want insecure authorization endpoint rejection", err)
	}
}

func TestOIDCVerifierRejectsJWKSWithoutVerificationKey(t *testing.T) {
	privateKey := newTestRSAKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		key := testJWK("encryption-key", &privateKey.PublicKey)
		key["key_ops"] = []string{"encrypt"}
		writeJSON(t, response, map[string]any{"keys": []any{key}})
	}))
	defer server.Close()

	_, err := NewOIDCVerifier(context.Background(), OIDCConfig{
		Issuer:     server.URL,
		JWKSURL:    server.URL,
		Audience:   "sendgrid-mcp-client",
		HTTPClient: server.Client(),
	})
	if err == nil || !strings.Contains(err.Error(), "no usable RSA signing keys") {
		t.Fatalf("NewOIDCVerifier error = %v, want key_ops rejection", err)
	}
}

func TestOIDCDiscoveryCandidatesIncludePathIssuers(t *testing.T) {
	candidates := discoveryCandidates("https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize")
	for _, expected := range []string{
		"https://login.microsoftonline.com/tenant-id/v2.0/.well-known/openid-configuration",
		"https://login.microsoftonline.com/.well-known/oauth-authorization-server/tenant-id/v2.0",
	} {
		if !contains(candidates, expected) {
			t.Fatalf("discovery candidates %#v do not contain %q", candidates, expected)
		}
	}
}

func TestFetchJSONRejectsOversizedAndTrailingDocuments(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(`{"value":"` + strings.Repeat("x", maxMetadataResponse) + `"}`))
		}))
		defer server.Close()

		var target map[string]any
		err := fetchJSON(context.Background(), server.Client(), server.URL, &target)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("fetchJSON error = %v, want response size rejection", err)
		}
	})

	t.Run("multiple values", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(`{} {}`))
		}))
		defer server.Close()

		var target map[string]any
		err := fetchJSON(context.Background(), server.Client(), server.URL, &target)
		if err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
			t.Fatalf("fetchJSON error = %v, want trailing JSON rejection", err)
		}
	})

	t.Run("HTTPS downgrade redirect", func(t *testing.T) {
		var targetRequests atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			targetRequests.Add(1)
			_, _ = response.Write([]byte(`{}`))
		}))
		defer target.Close()
		source := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Location", target.URL)
			response.WriteHeader(http.StatusFound)
		}))
		defer source.Close()

		var result map[string]any
		err := fetchJSON(context.Background(), source.Client(), source.URL, &result)
		if err == nil || !strings.Contains(err.Error(), "must not transition") {
			t.Fatalf("fetchJSON error = %v, want HTTPS downgrade rejection", err)
		}
		if got := targetRequests.Load(); got != 0 {
			t.Fatalf("downgrade redirect target received %d requests, want 0", got)
		}
	})

	t.Run("cross-host HTTPS redirect", func(t *testing.T) {
		var targetRequests atomic.Int32
		target := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			targetRequests.Add(1)
			_, _ = response.Write([]byte(`{}`))
		}))
		defer target.Close()
		source := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set("Location", testURLWithHostname(t, target.URL, "localhost"))
			response.WriteHeader(http.StatusFound)
		}))
		defer source.Close()

		var result map[string]any
		err := fetchJSON(context.Background(), source.Client(), source.URL, &result)
		if err == nil || !strings.Contains(err.Error(), "must not transition across origins") {
			t.Fatalf("fetchJSON error = %v, want cross-host HTTPS redirect rejection", err)
		}
		if got := targetRequests.Load(); got != 0 {
			t.Fatalf("cross-host HTTPS redirect target received %d requests, want 0", got)
		}
	})
}

func TestValidateURLTransitionNormalizesDefaultPorts(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		source string
		target string
	}{
		{
			name:   "implicit to explicit HTTPS port",
			source: "https://identity.example/discovery",
			target: "https://IDENTITY.EXAMPLE:443/jwks",
		},
		{
			name:   "explicit to implicit HTTPS port",
			source: "https://identity.example:443/discovery",
			target: "https://identity.example/jwks",
		},
		{
			name:   "implicit to explicit loopback HTTP port",
			source: "http://localhost/discovery",
			target: "http://LOCALHOST:80/jwks",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := validateURLTransition(testCase.source, testCase.target); err != nil {
				t.Fatalf("validateURLTransition failed: %v", err)
			}
		})
	}
	if err := validateURLTransition(
		"https://identity.example/discovery",
		"https://identity.example:8443/jwks",
	); err == nil {
		t.Fatal("validateURLTransition accepted a non-default cross-origin port")
	}
}

func TestOIDCVerifierCoalescesConcurrentUnknownKeyRefresh(t *testing.T) {
	firstKey := newTestRSAKey(t)
	rotatedKey := newTestRSAKey(t)
	var jwksRequests atomic.Int32
	var rotated atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/jwks" {
			http.NotFound(response, request)
			return
		}
		jwksRequests.Add(1)
		keyID := "first-key"
		publicKey := &firstKey.PublicKey
		if rotated.Load() {
			keyID = "rotated-key"
			publicKey = &rotatedKey.PublicKey
		}
		writeJSON(t, response, map[string]any{"keys": []any{testJWK(keyID, publicKey)}})
	}))
	defer server.Close()

	verifier, err := NewOIDCVerifier(context.Background(), OIDCConfig{
		Issuer:     server.URL,
		JWKSURL:    server.URL + "/jwks",
		Audience:   "sendgrid-mcp-client",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewOIDCVerifier failed: %v", err)
	}
	rotated.Store(true)
	now := time.Now()
	token := signTestToken(t, rotatedKey, "rotated-key", jwt.MapClaims{
		"iss": server.URL,
		"aud": "sendgrid-mcp-client",
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"sub": "alice-subject",
	})

	const callers = 20
	start := make(chan struct{})
	errors := make(chan error, callers)
	var waitGroup sync.WaitGroup
	waitGroup.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer waitGroup.Done()
			<-start
			_, verifyErr := verifier.Verify(context.Background(), token)
			errors <- verifyErr
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errors)
	for verifyErr := range errors {
		if verifyErr != nil {
			t.Errorf("Verify failed after key rotation: %v", verifyErr)
		}
	}
	if got := jwksRequests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want 2 (startup plus one coalesced refresh)", got)
	}
	for _, missingKeyID := range []string{"missing-key-1", "missing-key-2"} {
		missingKeyToken := signTestToken(t, rotatedKey, missingKeyID, jwt.MapClaims{
			"iss": server.URL,
			"aud": "sendgrid-mcp-client",
			"exp": now.Add(time.Minute).Unix(),
			"iat": now.Add(-time.Minute).Unix(),
			"sub": "alice-subject",
		})
		if _, err := verifier.Verify(context.Background(), missingKeyToken); err == nil {
			t.Fatalf("token with %q was unexpectedly accepted", missingKeyID)
		}
	}
	if got := jwksRequests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d after throttled cache misses, want 2", got)
	}
}

func TestVerifiedBearerMiddlewareStoresOnlyVerifiedClaims(t *testing.T) {
	verifier := &fakeTokenVerifier{
		claims: map[string]any{"sub": "verified-user"},
	}
	handler := VerifiedBearerMiddleware(verifier)(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		claims, ok := VerifiedClaimsFromContext(request.Context())
		if !ok || claims["sub"] != "verified-user" {
			t.Fatalf("missing verified claims: %#v", claims)
		}
		response.WriteHeader(http.StatusNoContent)
	}))

	request := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("{}"))
	request.Header.Set("Authorization", "Bearer signed-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || verifier.token != "signed-token" {
		t.Fatalf("unexpected middleware result: status=%d token=%q", response.Code, verifier.token)
	}

	verifier.err = context.Canceled
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token status = %d, want 401", response.Code)
	}

	noHeader := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	response = httptest.NewRecorder()
	VerifiedBearerMiddleware(verifier)(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(response, noHeader)
	if response.Code != http.StatusAccepted {
		t.Fatalf("headerless request status = %d, want pass-through", response.Code)
	}
}

type fakeTokenVerifier struct {
	claims map[string]any
	token  string
	err    error
}

func (f *fakeTokenVerifier) Verify(_ context.Context, token string) (map[string]any, error) {
	f.token = token
	return f.claims, f.err
}

func newTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func testJWK(keyID string, key *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, keyID string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	value, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return value
}

func cloneMap(source jwt.MapClaims, key string, value any) jwt.MapClaims {
	result := jwt.MapClaims{}
	for claim, claimValue := range source {
		result[claim] = claimValue
	}
	if key != "" {
		result[key] = value
	}
	return result
}

func testURLWithHostname(t *testing.T, value, hostname string) string {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("parse test URL %q: %v", value, err)
	}
	parsed.Host = net.JoinHostPort(hostname, parsed.Port())
	return parsed.String()
}

func writeJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Fatalf("write JSON: %v", err)
	}
}
