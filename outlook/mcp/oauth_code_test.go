package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"sync"
	"testing"

	"github.com/viant/mcp-toolbox/outlook/graph"
)

func TestAuthCodeStartHandlerRedirectsToAuthorizeURL(t *testing.T) {
	svc := NewService(&Config{
		ClientID:          "client-id",
		TenantID:          "common",
		SecretsBase:       t.TempDir(),
		CallbackBaseURL:   "http://outlook-mcp.local",
		AuthFlow:          string(graph.AuthFlowAuthCode),
		OAuthRedirectPath: "/outlook/auth/callback",
		GraphScopes:       []string{"Mail.Send"},
	})
	req := httptest.NewRequest(http.MethodGet, "/outlook/auth/start?alias=personal&tenant=common", nil)
	rec := httptest.NewRecorder()

	svc.DeviceStartHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected redirect, got status %d body %q", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	parsed, err := neturl.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect location: %v", err)
	}
	if got, want := parsed.Host, "login.microsoftonline.com"; got != want {
		t.Fatalf("unexpected auth host: got %q want %q", got, want)
	}
	if got, want := parsed.Query().Get("client_id"), "client-id"; got != want {
		t.Fatalf("unexpected client_id: got %q want %q", got, want)
	}
	if got := parsed.Query().Get("state"); got == "" {
		t.Fatalf("expected state in authorize URL")
	}
	if got := parsed.Query().Get("code_challenge"); got == "" {
		t.Fatalf("expected code_challenge in authorize URL")
	}
	if got, want := parsed.Query().Get("redirect_uri"), "http://outlook-mcp.local/outlook/auth/callback"; got != want {
		t.Fatalf("unexpected redirect_uri: got %q want %q", got, want)
	}
}

func TestGraphScopesDefaultDependsOnAuthFlow(t *testing.T) {
	device := NewService(&Config{SecretsBase: t.TempDir()})
	if got, want := device.GraphScopes(), graph.DefaultScopes(); !equalStrings(got, want) {
		t.Fatalf("unexpected device scopes: got %v want %v", got, want)
	}
	authCode := NewService(&Config{SecretsBase: t.TempDir(), AuthFlow: string(graph.AuthFlowAuthCode)})
	if got, want := authCode.GraphScopes(), graph.DefaultOAuthScopes(); !equalStrings(got, want) {
		t.Fatalf("unexpected auth-code scopes: got %v want %v", got, want)
	}
}

func TestStartAuthCodeSessionConcurrentCallsReuseState(t *testing.T) {
	svc := NewService(&Config{
		ClientID:        "client-id",
		TenantID:        "common",
		SecretsBase:     t.TempDir(),
		CallbackBaseURL: "http://outlook-mcp.local",
		AuthFlow:        string(graph.AuthFlowAuthCode),
		GraphScopes:     []string{"Mail.Send"},
	})
	const workers = 16
	results := make(chan *PendingAuth, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- svc.startAuthSession(context.Background(), "personal", "common", []string{"Mail.Send"})
		}()
	}
	wg.Wait()
	close(results)

	var first *PendingAuth
	for session := range results {
		if session == nil {
			t.Fatalf("expected session")
		}
		if first == nil {
			first = session
			if first.State == "" || first.CodeVerifier == "" || first.AuthURL == "" {
				t.Fatalf("expected initialized auth-code session, got %#v", first)
			}
			continue
		}
		if session.UUID != first.UUID || session.State != first.State || session.CodeVerifier != first.CodeVerifier || session.AuthURL != first.AuthURL {
			t.Fatalf("expected concurrent start to reuse one session, first=%#v got=%#v", first, session)
		}
	}
}

func TestOAuthCallbackStoresTokenAndCompletesSession(t *testing.T) {
	scopes := []string{"Mail.Send"}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse token request: %v", err)
		}
		if got, want := r.Form.Get("code"), "auth-code"; got != want {
			t.Fatalf("unexpected code: got %q want %q", got, want)
		}
		if got := r.Form.Get("code_verifier"); got == "" {
			t.Fatalf("expected code_verifier")
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

	svc := NewService(&Config{
		ClientID:          "client-id",
		TenantID:          "common",
		SecretsBase:       t.TempDir(),
		CallbackBaseURL:   "http://outlook-mcp.local",
		AuthFlow:          string(graph.AuthFlowAuthCode),
		OAuthRedirectPath: "/outlook/auth/callback",
		GraphScopes:       scopes,
	})
	svc.graphMgr = graph.NewManagerWithConfig(&graph.ManagerConfig{
		ClientID:              "client-id",
		StorageDir:            svc.SecretsBase(),
		AuthFlow:              graph.AuthFlowAuthCode,
		OAuthRedirectURL:      "http://outlook-mcp.local/outlook/auth/callback",
		OAuthScopes:           scopes,
		OAuthAuthURLOverride:  "http://localhost/authorize",
		OAuthTokenURLOverride: tokenServer.URL,
		OAuthHTTPClient:       tokenServer.Client(),
	})

	session := svc.startAuthSession(context.Background(), "personal", "common", scopes)
	if session == nil || session.State == "" {
		t.Fatalf("expected auth-code session with state, got %#v", session)
	}
	req := httptest.NewRequest(http.MethodGet, "/outlook/auth/callback?state="+neturl.QueryEscape(session.State)+"&code=auth-code", nil)
	rec := httptest.NewRecorder()

	svc.OAuthCallbackHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected callback status 200, got %d body %q", rec.Code, rec.Body.String())
	}
	current, ok := svc.pending.Get(session.UUID)
	if !ok {
		t.Fatalf("expected pending session to remain available")
	}
	if current.Status != AuthStatusAuthenticated {
		t.Fatalf("expected authenticated status, got %q", current.Status)
	}
	check := svc.graphMgr.AuthCheck(context.Background(), "personal", "common", scopes)
	if check.Status != graph.AuthCheckReady {
		t.Fatalf("expected saved token to be ready, got %q err=%v", check.Status, check.Err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOAuthCallbackRejectsUnknownState(t *testing.T) {
	svc := NewService(&Config{
		ClientID:        "client-id",
		TenantID:        "common",
		SecretsBase:     t.TempDir(),
		CallbackBaseURL: "http://outlook-mcp.local",
		AuthFlow:        string(graph.AuthFlowAuthCode),
	})
	req := httptest.NewRequest(http.MethodGet, "/outlook/auth/callback?state=missing&code=auth-code", nil)
	rec := httptest.NewRecorder()

	svc.OAuthCallbackHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}
