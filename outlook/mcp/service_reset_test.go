package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeviceResetHandlerRequiresPost(t *testing.T) {
	svc := NewService(&Config{SecretsBase: t.TempDir()})
	req := httptest.NewRequest(http.MethodGet, "/outlook/auth/reset?alias=personal", nil)
	rec := httptest.NewRecorder()

	svc.DeviceResetHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rec.Code)
	}
}

func TestDeviceResetHandlerRequiresAlias(t *testing.T) {
	svc := NewService(&Config{SecretsBase: t.TempDir()})
	req := httptest.NewRequest(http.MethodPost, "/outlook/auth/reset", nil)
	req.Header.Set("Authorization", "Bearer "+testJWT(t, map[string]any{"email": "alice@example.com"}))
	rec := httptest.NewRecorder()

	svc.DeviceResetHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestCompletedAuthSessionCompletesExistingPendingSession(t *testing.T) {
	svc := NewService(&Config{SecretsBase: t.TempDir()})
	scopes := []string{"scope"}
	ctx := contextWithBearer(context.Background(), testJWT(t, map[string]any{"email": "alice@example.com"}))
	pending, created := svc.pending.GetOrCreate("alice@example.com", "personal", "consumers", scopes, time.Hour, func() string {
		return "pending-session"
	})
	if !created {
		t.Fatalf("expected pending session to be created")
	}

	session, err := svc.completedAuthSession(ctx, "personal", "consumers", scopes)
	if err != nil {
		t.Fatalf("completedAuthSession failed: %v", err)
	}
	if session.UUID != pending.UUID {
		t.Fatalf("expected existing pending session to be reused, got %q want %q", session.UUID, pending.UUID)
	}
	if session.Status != AuthStatusAuthenticated {
		t.Fatalf("expected authenticated status, got %q", session.Status)
	}
	select {
	case <-pending.Done():
	default:
		t.Fatalf("expected pending session to be signaled")
	}
}
