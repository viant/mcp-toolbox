package graph

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/viant/mcp-protocol/authorization"
	"golang.org/x/oauth2"
)

func TestClientCacheKeyNormalization(t *testing.T) {
	m := NewManager("", "")
	ns := "default"
	a, tnt := "aliasA", "tenantX"
	k1 := m.clientKey(ns, a, tnt, []string{"scope2", "scope1"})
	k2 := m.clientKey(ns, a, tnt, []string{"scope1", "scope2"})
	if k1 != k2 {
		t.Fatalf("expected normalized keys to be equal, got %q vs %q", k1, k2)
	}
}

func TestNeedsInteractiveWithoutAuthRecord(t *testing.T) {
	m := NewManager("client-id", t.TempDir())
	if !m.NeedsInteractive(context.Background(), "personal", "consumers", []string{"scope"}) {
		t.Fatalf("expected missing auth record to require interactive auth")
	}
}

func TestAuthCheckWithoutAuthRecord(t *testing.T) {
	m := NewManager("client-id", t.TempDir())
	result := m.AuthCheck(context.Background(), "personal", "consumers", []string{"scope"})
	if result.Status != AuthCheckNeedsInteractive {
		t.Fatalf("unexpected status: got %q want %q", result.Status, AuthCheckNeedsInteractive)
	}
	if result.Reason != "no_usable_auth_record" {
		t.Fatalf("unexpected reason: %q", result.Reason)
	}
}

func TestAuthCheckWithCorruptAuthRecordNeedsInteractive(t *testing.T) {
	storageDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(storageDir, "default_personal_auth_record.json"), []byte(`{not-json`), 0o600); err != nil {
		t.Fatalf("failed to write auth record: %v", err)
	}
	m := NewManager("client-id", storageDir)
	result := m.AuthCheck(context.Background(), "personal", "consumers", []string{"scope"})
	if result.Status != AuthCheckNeedsInteractive {
		t.Fatalf("unexpected status: got %q want %q", result.Status, AuthCheckNeedsInteractive)
	}
}

func TestManagerAuthRecordNamespaceDefaultsToEmail(t *testing.T) {
	storageDir := t.TempDir()
	m := NewManager("client-id", storageDir)
	ctx := graphContextWithBearer(context.Background(), graphTestJWT(t, map[string]any{
		"email": "alice@example.com",
		"sub":   "alice-subject",
	}))

	d, err := m.ns.Namespace(ctx)
	if err != nil {
		t.Fatalf("failed to resolve namespace: %v", err)
	}
	if got, want := d.Name, "alice@example.com"; got != want {
		t.Fatalf("unexpected namespace: got %q want %q", got, want)
	}
	if got, want := m.authRecordURL(d.Name, "personal"), filepath.Join(storageDir, "alice_example.com_personal_auth_record.json"); got != want {
		t.Fatalf("unexpected auth record URL: got %q want %q", got, want)
	}
}

func TestManagerAuthRecordNamespaceCanUseSubject(t *testing.T) {
	storageDir := t.TempDir()
	m := NewManagerWithNamespaceClaimKeys("client-id", storageDir, []string{"sub", "email"})
	ctx := graphContextWithBearer(context.Background(), graphTestJWT(t, map[string]any{
		"email": "alice@example.com",
		"sub":   "alice-subject",
	}))

	d, err := m.ns.Namespace(ctx)
	if err != nil {
		t.Fatalf("failed to resolve namespace: %v", err)
	}
	if got, want := d.Name, "alice-subject"; got != want {
		t.Fatalf("unexpected namespace: got %q want %q", got, want)
	}
	if got, want := m.authRecordURL(d.Name, "personal"), filepath.Join(storageDir, "alice-subject_personal_auth_record.json"); got != want {
		t.Fatalf("unexpected auth record URL: got %q want %q", got, want)
	}
}

func TestIsTransientAuthProviderError(t *testing.T) {
	tests := []error{
		context.DeadlineExceeded,
		&net.DNSError{Err: "no such host", Name: "login.microsoftonline.com"},
		fmt.Errorf("unable to resolve an endpoint: server response error: %w", context.DeadlineExceeded),
		fmt.Errorf("Post %q: i/o timeout", "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"),
	}
	for _, err := range tests {
		if !IsTransientAuthProviderError(err) {
			t.Fatalf("expected transient auth provider error for %v", err)
		}
	}
}

func graphContextWithBearer(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authorization.TokenKey, &authorization.Token{Token: "Bearer " + token})
}

func graphTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	encode := func(v any) string {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("failed to marshal jwt part: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return encode(map[string]any{"alg": "none", "typ": "JWT"}) + "." + encode(claims) + "."
}

func TestTransientAuthProviderErrorMessageIsSanitized(t *testing.T) {
	err := NewTransientAuthProviderError(fmt.Errorf("raw provider detail"))
	if got := UserMessageForAuthError(err); got != TransientAuthProviderMessage {
		t.Fatalf("unexpected message: got %q want %q", got, TransientAuthProviderMessage)
	}
	if got := err.Error(); got != TransientAuthProviderMessage {
		t.Fatalf("unexpected error string: got %q want %q", got, TransientAuthProviderMessage)
	}
}

func TestResetAuthClearsMemoryAndAuthRecord(t *testing.T) {
	ctx := context.Background()
	storageDir := t.TempDir()
	m := NewManager("client/id", storageDir)
	alias := "personal"
	tenant := "consumers"
	scopes := []string{"scope2", "scope1"}

	recordPath := filepath.Join(storageDir, "default_personal_auth_record.json")
	if err := os.WriteFile(recordPath, []byte(`{"homeAccountId":"id"}`), 0o600); err != nil {
		t.Fatalf("failed to write auth record: %v", err)
	}

	clientKey := m.clientKey("default", alias, tenant, scopes)
	m.mu.Lock()
	m.clients[clientKey] = &msgraphsdk.GraphServiceClient{}
	m.creds[clientKey] = nil
	m.waiters[clientKey] = []chan struct{}{make(chan struct{})}
	m.mu.Unlock()

	result, err := m.ResetAuth(ctx, alias, tenant, scopes, false)
	if err != nil {
		t.Fatalf("ResetAuth failed: %v", err)
	}
	if !result.ClearedAuthRecord {
		t.Fatalf("expected auth record to be cleared")
	}
	if !result.ClearedMemory {
		t.Fatalf("expected memory cache to be cleared")
	}
	if _, err := os.Stat(recordPath); !os.IsNotExist(err) {
		t.Fatalf("expected auth record file to be removed, stat err=%v", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.clients[clientKey]; ok {
		t.Fatalf("expected graph client cache entry to be removed")
	}
	if _, ok := m.creds[clientKey]; ok {
		t.Fatalf("expected credential cache entry to be removed")
	}
	if _, ok := m.waiters[clientKey]; ok {
		t.Fatalf("expected waiter entry to be removed")
	}
}

func TestResetAuthClearsAllOAuthTokensForAliasAcrossScopeChanges(t *testing.T) {
	ctx := context.Background()
	storageDir := t.TempDir()
	m := NewManagerWithConfig(&ManagerConfig{
		ClientID:   "client/id",
		StorageDir: storageDir,
		AuthFlow:   AuthFlowAuthCode,
	})
	alias := "personal"
	tenant := "common"
	oldScopes := []string{"Mail.Send"}
	newScopes := []string{"Mail.Send", "Mail.Read"}

	if err := m.saveOAuthToken(ctx, "default", alias, tenant, oldScopes, testOAuthToken("old-token")); err != nil {
		t.Fatalf("failed to save old token: %v", err)
	}
	if err := m.saveOAuthToken(ctx, "default", alias, tenant, newScopes, testOAuthToken("new-token")); err != nil {
		t.Fatalf("failed to save new token: %v", err)
	}

	result, err := m.ResetAuth(ctx, alias, tenant, newScopes, false)
	if err != nil {
		t.Fatalf("ResetAuth failed: %v", err)
	}
	if !result.ClearedOAuthToken {
		t.Fatalf("expected OAuth tokens to be cleared")
	}
	if rec, err := m.loadOAuthToken(ctx, "default", alias, tenant, oldScopes); err != nil || rec != nil {
		t.Fatalf("expected old-scope token to be removed, got rec=%v err=%v", rec, err)
	}
	if rec, err := m.loadOAuthToken(ctx, "default", alias, tenant, newScopes); err != nil || rec != nil {
		t.Fatalf("expected new-scope token to be removed, got rec=%v err=%v", rec, err)
	}
}

func testOAuthToken(accessToken string) *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Hour),
	}
}

func TestPersistentCacheNameIsStableAndSafe(t *testing.T) {
	m := NewManager("client/id with spaces", "")
	if got, want := m.persistentCacheName(), "mcp-toolbox-outlook-client_id_with_spaces"; got != want {
		t.Fatalf("unexpected cache name: got %q want %q", got, want)
	}
}
