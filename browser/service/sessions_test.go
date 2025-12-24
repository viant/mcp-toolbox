package service

import (
	"context"
	"testing"
)

func TestService_Sessions(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	svc.sessions["s1"] = &Session{ID: "s1", Browser: ChromeBrowser}
	svc.sessions["s2"] = &Session{ID: "s2", Browser: FirefoxBrowser, driver: nil}

	out, err := svc.Sessions(context.Background(), &SessionsInput{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Sessions) != 0 {
		t.Fatalf("expected only open sessions, got %d", len(out.Sessions))
	}

	out, err = svc.Sessions(context.Background(), &SessionsInput{IncludeAll: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(out.Sessions))
	}
}
