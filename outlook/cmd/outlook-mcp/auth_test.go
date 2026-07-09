package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	flags "github.com/jessevdk/go-flags"
	"github.com/viant/mcp-protocol/authorization"
	"github.com/viant/mcp-toolbox/outlook/graph"
)

func TestPassiveBearerAuthorizerInjectsAuthorizationToken(t *testing.T) {
	var got string
	next := passiveBearerAuthorizer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := r.Context().Value(authorization.TokenKey).(*authorization.Token)
		if ok && token != nil {
			got = token.Token
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	next.ServeHTTP(httptest.NewRecorder(), req)

	if got != "Bearer test-token" {
		t.Fatalf("unexpected token: got %q want %q", got, "Bearer test-token")
	}
}

func TestPassiveBearerAuthorizerAllowsMissingAuthorization(t *testing.T) {
	called := false
	next := passiveBearerAuthorizer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if token := r.Context().Value(authorization.TokenKey); token != nil {
			t.Fatalf("unexpected auth token in context: %v", token)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	next.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if !called {
		t.Fatal("expected next handler to be called")
	}
}

func TestOptionsParsesNamespaceClaimKeysFlag(t *testing.T) {
	var opts Options
	if _, err := flags.NewParser(&opts, flags.Default).ParseArgs([]string{"--namespace-claim-keys", "sub,email"}); err != nil {
		t.Fatalf("failed to parse options: %v", err)
	}
	if got, want := opts.NamespaceClaimKeys, "sub,email"; got != want {
		t.Fatalf("unexpected namespace claim keys option: got %q want %q", got, want)
	}
}

func TestOptionsParsesAuthCodeFlags(t *testing.T) {
	var opts Options
	args := []string{
		"--auth-flow", "auth-code",
		"--oauth-redirect-path", "/outlook/auth/callback",
		"--graph-scopes", "openid,offline_access,Mail.Send",
	}
	if _, err := flags.NewParser(&opts, flags.Default).ParseArgs(args); err != nil {
		t.Fatalf("failed to parse options: %v", err)
	}
	if got, want := opts.AuthFlow, "auth-code"; got != want {
		t.Fatalf("unexpected auth flow: got %q want %q", got, want)
	}
	if got, want := opts.OAuthRedirectPath, "/outlook/auth/callback"; got != want {
		t.Fatalf("unexpected redirect path: got %q want %q", got, want)
	}
	if got, want := opts.GraphScopes, "openid,offline_access,Mail.Send"; got != want {
		t.Fatalf("unexpected graph scopes: got %q want %q", got, want)
	}
}

func TestServiceConfigFromOptionsParsesNamespaceClaimKeys(t *testing.T) {
	cfg := serviceConfigFromOptions(Options{NamespaceClaimKeys: " sub, email "}, "http://localhost:7788")
	if !slices.Equal(cfg.NamespaceClaimKeys, []string{"sub", "email"}) {
		t.Fatalf("unexpected namespace claim keys: got %v", cfg.NamespaceClaimKeys)
	}
}

func TestServiceConfigFromOptionsParsesAuthCodeConfig(t *testing.T) {
	cfg := serviceConfigFromOptions(Options{
		AuthFlow:          "auth-code",
		OAuthRedirectPath: "/outlook/auth/callback",
		GraphScopes:       "openid offline_access Mail.Send",
	}, "http://localhost:7788")
	if got, want := cfg.AuthFlow, string(graph.AuthFlowAuthCode); got != want {
		t.Fatalf("unexpected auth flow: got %q want %q", got, want)
	}
	if got, want := cfg.OAuthRedirectPath, "/outlook/auth/callback"; got != want {
		t.Fatalf("unexpected redirect path: got %q want %q", got, want)
	}
	if !slices.Equal(cfg.GraphScopes, []string{"openid", "offline_access", "Mail.Send"}) {
		t.Fatalf("unexpected graph scopes: got %v", cfg.GraphScopes)
	}
}

func TestApplyOptionDefaultsPreservesDeviceScopeDefault(t *testing.T) {
	opts := Options{}
	applyOptionDefaults(&opts)
	if got, want := opts.AuthFlow, string(graph.AuthFlowDevice); got != want {
		t.Fatalf("unexpected auth flow: got %q want %q", got, want)
	}
	if got, want := opts.OAuthRedirectPath, "/outlook/auth/callback"; got != want {
		t.Fatalf("unexpected redirect path: got %q want %q", got, want)
	}
	if opts.GraphScopes != "" {
		t.Fatalf("expected graph scopes to remain empty for default device flow, got %q", opts.GraphScopes)
	}
}

func TestServiceConfigFromOptionsDoesNotUseNamespaceClaimEnvFallback(t *testing.T) {
	t.Setenv("OUTLOOK_NAMESPACE_CLAIM_KEYS", "sub,email")
	cfg := serviceConfigFromOptions(Options{}, "http://localhost:7788")
	if !slices.Equal(cfg.NamespaceClaimKeys, []string{"email", "sub"}) {
		t.Fatalf("unexpected namespace claim keys: got %v", cfg.NamespaceClaimKeys)
	}
}

func TestApplyOptionDefaultsDoesNotUseNamespaceClaimEnvFallback(t *testing.T) {
	t.Setenv("OUTLOOK_NAMESPACE_CLAIM_KEYS", "sub,email")
	opts := Options{}
	applyOptionDefaults(&opts)
	if opts.NamespaceClaimKeys != "" {
		t.Fatalf("unexpected namespace claim keys option from env fallback: got %q", opts.NamespaceClaimKeys)
	}
}
