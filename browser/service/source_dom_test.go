package service

import (
	"context"
	"testing"
)

func TestTruncateUTF8ByBytes(t *testing.T) {
	s := "a€b" // "€" is 3 bytes
	out, truncated := truncateUTF8ByBytes(s, 2)
	if !truncated {
		t.Fatalf("expected truncated")
	}
	if out != "a" {
		t.Fatalf("expected valid utf-8 truncation, got %q", out)
	}
}

func TestService_GetSource_UnknownSession(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	_, err := svc.GetSource(context.Background(), &GetSourceInput{SessionID: "missing"})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestService_GetDOM_UnknownSession(t *testing.T) {
	svc := NewService(&Config{UseData: true})
	_, err := svc.GetDOM(context.Background(), &GetDOMInput{SessionID: "missing"})
	if err == nil {
		t.Fatalf("expected error")
	}
}
