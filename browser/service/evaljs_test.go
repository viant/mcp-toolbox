package service

import (
	"context"
	"testing"
)

func TestService_EvalJS_UnknownSession(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	_, err := svc.EvalJS(context.Background(), &EvalJSInput{SessionID: "missing", Script: "return 1"})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestService_EvalJS_SessionNotOpen(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	svc.sessions["localhost:4444"] = &Session{ID: "localhost:4444"}

	_, err := svc.EvalJS(context.Background(), &EvalJSInput{SessionID: "localhost:4444", Script: "return 1"})
	if err == nil {
		t.Fatalf("expected error")
	}
}
