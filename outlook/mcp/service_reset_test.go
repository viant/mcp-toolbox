package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
	rec := httptest.NewRecorder()

	svc.DeviceResetHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
}
