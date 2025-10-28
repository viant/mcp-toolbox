package graph

import (
    "context"
    "testing"
    msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

func TestClientCacheKeyNormalization(t *testing.T) {
    m := NewManager("", "")
    a, tnt := "aliasA", "tenantX"
    k1 := m.clientKey(a, tnt, []string{"scope2", "scope1"})
    k2 := m.clientKey(a, tnt, []string{"scope1", "scope2"})
    if k1 != k2 {
        t.Fatalf("expected normalized keys to be equal, got %q vs %q", k1, k2)
    }
}

func TestClientReturnsCachedInstance(t *testing.T) {
    m := NewManager("", "")
    alias, tenant := "acc", "ten"
    scopes := []string{"s1", "s2"}
    key := m.clientKey(alias, tenant, scopes)
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

