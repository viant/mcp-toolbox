package graph

import (
	"context"
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

func TestClientReturnsCachedInstance(t *testing.T) {
	m := NewManager("", "")
	ns := "default"
	alias, tenant := "acc", "ten"
	scopes := []string{"s1", "s2"}
	key := m.clientKey(ns, alias, tenant, scopes)
	want := &msgraphsdk.GraphServiceClient{}
	m.mu.Lock()
	m.clients[key] = want
	m.mu.Unlock()

	got, err := m.Client(context.Background(), alias, tenant, []string{"s2", "s1"}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("expected cached client to be returned")
	}
}

func TestNeedsInteractiveWithoutAuthRecord(t *testing.T) {
	m := NewManager("client-id", t.TempDir())
	if !m.NeedsInteractive(context.Background(), "personal", "consumers", []string{"scope"}) {
		t.Fatalf("expected missing auth record to require interactive auth")
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
	m.creds["default|"+alias] = nil
	m.waiters["default|"+alias] = []chan struct{}{make(chan struct{})}
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
	if _, ok := m.creds["default|"+alias]; ok {
		t.Fatalf("expected credential cache entry to be removed")
	}
	if _, ok := m.waiters["default|"+alias]; ok {
		t.Fatalf("expected waiter entry to be removed")
	}
}

func TestPersistentCacheNameIsStableAndSafe(t *testing.T) {
	m := NewManager("client/id with spaces", "")
	if got, want := m.persistentCacheName(), "mcp-toolbox-outlook-client_id_with_spaces"; got != want {
		t.Fatalf("unexpected cache name: got %q want %q", got, want)
	}
}
