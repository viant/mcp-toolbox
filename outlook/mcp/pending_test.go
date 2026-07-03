package mcp

import (
	"testing"
	"time"
)

func TestPendingAuthsClearAlias(t *testing.T) {
	p := NewPendingAuths()
	p.Put(&PendingAuth{UUID: "one", Alias: "personal", Namespace: "default", done: make(chan struct{}, 1)})
	p.Put(&PendingAuth{UUID: "two", Alias: "work", Namespace: "default", done: make(chan struct{}, 1)})
	p.Put(&PendingAuth{UUID: "three", Alias: "personal", Namespace: "other", done: make(chan struct{}, 1)})

	cleared := p.ClearAlias("default", "personal")
	if len(cleared) != 1 || cleared[0] != "one" {
		t.Fatalf("unexpected cleared ids: %#v", cleared)
	}
	if _, ok := p.Get("one"); ok {
		t.Fatalf("expected matching pending auth to be removed")
	}
	if _, ok := p.Get("two"); !ok {
		t.Fatalf("expected different alias in same namespace to remain")
	}
	if _, ok := p.Get("three"); !ok {
		t.Fatalf("expected same alias in different namespace to remain")
	}
}

func TestPendingAuthsGetOrCreateReusesActiveSession(t *testing.T) {
	p := NewPendingAuths()
	next := 0
	newID := func() string {
		next++
		if next == 1 {
			return "one"
		}
		return "two"
	}

	first, created := p.GetOrCreate("default", "personal", "consumers", []string{"scope2", "scope1"}, time.Minute, newID)
	if !created {
		t.Fatalf("expected first call to create a session")
	}
	second, created := p.GetOrCreate("default", "personal", "consumers", []string{"scope1", "scope2"}, time.Minute, newID)
	if created {
		t.Fatalf("expected equivalent active session to be reused")
	}
	if second.UUID != first.UUID {
		t.Fatalf("expected same uuid, got %q vs %q", second.UUID, first.UUID)
	}
}

func TestPendingAuthsGetOrCreateSeparatesTenant(t *testing.T) {
	p := NewPendingAuths()
	ids := []string{"one", "two"}
	newID := func() string {
		id := ids[0]
		ids = ids[1:]
		return id
	}

	first, created := p.GetOrCreate("default", "personal", "consumers", []string{"scope"}, time.Minute, newID)
	if !created {
		t.Fatalf("expected first call to create a session")
	}
	second, created := p.GetOrCreate("default", "personal", "organizations", []string{"scope"}, time.Minute, newID)
	if !created {
		t.Fatalf("expected different tenant to create a separate session")
	}
	if second.UUID == first.UUID {
		t.Fatalf("expected separate uuid for different tenant")
	}
}

func TestPendingAuthsGetMarksExpiredAndSignalsDone(t *testing.T) {
	p := NewPendingAuths()
	p.Put(&PendingAuth{
		UUID:      "expired",
		Alias:     "personal",
		TenantID:  "consumers",
		Namespace: "default",
		ExpiresAt: time.Now().Add(-time.Second),
		done:      make(chan struct{}),
	})

	session, ok := p.Get("expired")
	if !ok {
		t.Fatalf("expected session to exist")
	}
	if session.Status != AuthStatusExpired {
		t.Fatalf("expected expired status, got %q", session.Status)
	}
	select {
	case <-session.Done():
	default:
		t.Fatalf("expected expired session to signal completion")
	}
}
