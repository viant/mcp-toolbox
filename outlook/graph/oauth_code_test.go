package graph

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestAuthCodeURLIncludesStateAndPKCE(t *testing.T) {
	m := NewManagerWithConfig(&ManagerConfig{
		ClientID:         "client-id",
		StorageDir:       t.TempDir(),
		AuthFlow:         AuthFlowAuthCode,
		OAuthRedirectURL: "http://localhost:7788/outlook/auth/callback",
		OAuthScopes:      []string{"Mail.Send"},
	})

	verifier := "test-verifier"
	authURL := m.AuthCodeURL("common", []string{"Mail.Send"}, "state-123", verifier)
	parsed, err := neturl.Parse(authURL)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}
	query := parsed.Query()
	if got, want := query.Get("state"), "state-123"; got != want {
		t.Fatalf("unexpected state: got %q want %q", got, want)
	}
	if got, want := query.Get("client_id"), "client-id"; got != want {
		t.Fatalf("unexpected client_id: got %q want %q", got, want)
	}
	if got, want := query.Get("redirect_uri"), "http://localhost:7788/outlook/auth/callback"; got != want {
		t.Fatalf("unexpected redirect_uri: got %q want %q", got, want)
	}
	if got, want := query.Get("code_challenge_method"), "S256"; got != want {
		t.Fatalf("unexpected code challenge method: got %q want %q", got, want)
	}
	sum := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := query.Get("code_challenge"); got != wantChallenge {
		t.Fatalf("unexpected code challenge: got %q want %q", got, wantChallenge)
	}
	if !strings.Contains(query.Get("scope"), "Mail.Send") {
		t.Fatalf("expected Mail.Send scope, got %q", query.Get("scope"))
	}
}

func TestOAuthAuthCheckWithoutTokenNeedsInteractive(t *testing.T) {
	m := NewManagerWithConfig(&ManagerConfig{
		ClientID:         "client-id",
		StorageDir:       t.TempDir(),
		AuthFlow:         AuthFlowAuthCode,
		OAuthRedirectURL: "http://localhost/callback",
		OAuthScopes:      []string{"Mail.Send"},
	})

	result := m.AuthCheck(context.Background(), "personal", "common", []string{"Mail.Send"})
	if result.Status != AuthCheckNeedsInteractive {
		t.Fatalf("unexpected status: got %q want %q", result.Status, AuthCheckNeedsInteractive)
	}
	if result.Reason != "no_usable_oauth_token" {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
}

func TestOAuthAuthCheckWithValidTokenReady(t *testing.T) {
	ctx := context.Background()
	scopes := []string{"Mail.Send"}
	m := NewManagerWithConfig(&ManagerConfig{
		ClientID:         "client-id",
		StorageDir:       t.TempDir(),
		AuthFlow:         AuthFlowAuthCode,
		OAuthRedirectURL: "http://localhost/callback",
		OAuthScopes:      scopes,
	})
	if err := m.saveOAuthToken(ctx, "default", "personal", "common", scopes, &oauth2.Token{
		AccessToken:  "access-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("failed to save token: %v", err)
	}

	result := m.AuthCheck(ctx, "personal", "common", scopes)
	if result.Status != AuthCheckReady {
		t.Fatalf("unexpected status: got %q want %q err=%v", result.Status, AuthCheckReady, result.Err)
	}
}

func TestOAuthAuthCheckRefreshesExpiredToken(t *testing.T) {
	ctx := context.Background()
	scopes := []string{"Mail.Send"}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse token request: %v", err)
		}
		if got, want := r.Form.Get("grant_type"), "refresh_token"; got != want {
			t.Fatalf("unexpected grant_type: got %q want %q", got, want)
		}
		if got, want := r.Form.Get("refresh_token"), "old-refresh"; got != want {
			t.Fatalf("unexpected refresh token: got %q want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"token_type":    "Bearer",
			"refresh_token": "new-refresh",
			"expires_in":    3600,
		})
	}))
	defer tokenServer.Close()

	m := NewManagerWithConfig(&ManagerConfig{
		ClientID:              "client-id",
		StorageDir:            t.TempDir(),
		AuthFlow:              AuthFlowAuthCode,
		OAuthRedirectURL:      "http://localhost/callback",
		OAuthScopes:           scopes,
		OAuthAuthURLOverride:  "http://localhost/authorize",
		OAuthTokenURLOverride: tokenServer.URL,
		OAuthHTTPClient:       tokenServer.Client(),
	})
	if err := m.saveOAuthToken(ctx, "default", "personal", "common", scopes, &oauth2.Token{
		AccessToken:  "old-access",
		TokenType:    "Bearer",
		RefreshToken: "old-refresh",
		Expiry:       time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("failed to save token: %v", err)
	}

	result := m.AuthCheck(ctx, "personal", "common", scopes)
	if result.Status != AuthCheckReady {
		t.Fatalf("unexpected status: got %q want %q err=%v", result.Status, AuthCheckReady, result.Err)
	}
	rec, err := m.loadOAuthToken(ctx, "default", "personal", "common", scopes)
	if err != nil {
		t.Fatalf("failed to load refreshed token: %v", err)
	}
	if got, want := rec.AccessToken, "new-access"; got != want {
		t.Fatalf("unexpected access token: got %q want %q", got, want)
	}
	if got, want := rec.RefreshToken, "new-refresh"; got != want {
		t.Fatalf("unexpected refresh token: got %q want %q", got, want)
	}
}

func TestExchangeAuthCodeStoresToken(t *testing.T) {
	ctx := context.Background()
	scopes := []string{"Mail.Send"}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse token request: %v", err)
		}
		if got, want := r.Form.Get("grant_type"), "authorization_code"; got != want {
			t.Fatalf("unexpected grant_type: got %q want %q", got, want)
		}
		if got, want := r.Form.Get("code"), "auth-code"; got != want {
			t.Fatalf("unexpected code: got %q want %q", got, want)
		}
		if got, want := r.Form.Get("code_verifier"), "verifier"; got != want {
			t.Fatalf("unexpected verifier: got %q want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-token",
			"token_type":    "Bearer",
			"refresh_token": "refresh-token",
			"expires_in":    3600,
		})
	}))
	defer tokenServer.Close()

	m := NewManagerWithConfig(&ManagerConfig{
		ClientID:              "client-id",
		StorageDir:            t.TempDir(),
		AuthFlow:              AuthFlowAuthCode,
		OAuthRedirectURL:      "http://localhost/callback",
		OAuthScopes:           scopes,
		OAuthAuthURLOverride:  "http://localhost/authorize",
		OAuthTokenURLOverride: tokenServer.URL,
		OAuthHTTPClient:       tokenServer.Client(),
	})

	if err := m.ExchangeAuthCode(ctx, "default", "personal", "common", scopes, "auth-code", "verifier"); err != nil {
		t.Fatalf("ExchangeAuthCode failed: %v", err)
	}
	rec, err := m.loadOAuthToken(ctx, "default", "personal", "common", scopes)
	if err != nil {
		t.Fatalf("failed to load token: %v", err)
	}
	if got, want := rec.AccessToken, "access-token"; got != want {
		t.Fatalf("unexpected access token: got %q want %q", got, want)
	}
}
