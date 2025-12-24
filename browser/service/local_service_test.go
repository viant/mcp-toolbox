package service

import (
	"context"
	"testing"
)

func TestIsLocalHost(t *testing.T) {
	for _, host := range []string{"localhost", "LOCALHOST", "127.0.0.1", "::1", " ::1 "} {
		if !isLocalHost(host) {
			t.Fatalf("expected local host: %q", host)
		}
	}
	if isLocalHost("example.com") {
		t.Fatalf("expected non-local host")
	}
}

func TestEnsureLocalDriverService_SkipsNonDefaultRemote(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	sess := &Session{ID: "localhost:4444", Browser: ChromeBrowser}
	in := &OpenSessionInput{SessionID: "localhost:4444", Remote: "http://localhost:5555/wd/hub"}

	if err := svc.ensureLocalDriverService(context.Background(), sess, in); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sess.service != nil {
		t.Fatalf("expected service not started")
	}
}
