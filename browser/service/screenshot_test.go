package service

import (
	"context"
	"testing"
)

func TestService_Screenshot_UnknownSession(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	_, err := svc.Screenshot(context.Background(), &ScreenshotInput{SessionID: "missing"})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestService_Screenshot_SessionNotOpen(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	svc.sessions["localhost:4444"] = &Session{ID: "localhost:4444"}

	_, err := svc.Screenshot(context.Background(), &ScreenshotInput{SessionID: "localhost:4444"})
	if err == nil {
		t.Fatalf("expected error")
	}
}
