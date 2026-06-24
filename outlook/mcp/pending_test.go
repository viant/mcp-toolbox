package mcp

import "testing"

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
