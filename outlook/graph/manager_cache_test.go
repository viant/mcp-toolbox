package graph

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
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

func TestPersistentCacheNameIsStableAndSafe(t *testing.T) {
	m := NewManager("client/id with spaces", "")
	if got, want := m.persistentCacheName(), "mcp-toolbox-outlook-client_id_with_spaces"; got != want {
		t.Fatalf("unexpected cache name: got %q want %q", got, want)
	}
}
