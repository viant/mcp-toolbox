package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/viant/mcp-toolbox/outlook/graph"
)

func TestCustomAuthEndpointsRequireDirectBearerIdentity(t *testing.T) {
	svc := NewService(&Config{
		ClientID:        "client-id",
		TenantID:        "common",
		SecretsBase:     t.TempDir(),
		AuthFlow:        string(graph.AuthFlowAuthCode),
		GraphScopes:     []string{"Mail.Send"},
		CallbackBaseURL: "http://outlook-mcp.local",
	})
	identityContext := contextWithBearer(context.Background(), testJWT(t, map[string]any{"email": "alice@example.com"}))
	tests := []struct {
		name    string
		method  string
		path    string
		handler http.Handler
	}{
		{name: "start", method: http.MethodPost, path: "/outlook/auth/start?alias=personal", handler: svc.DeviceStartHandler()},
		{name: "check", method: http.MethodGet, path: "/outlook/auth/check?alias=personal", handler: svc.DeviceCheckHandler()},
		{name: "reset", method: http.MethodPost, path: "/outlook/auth/reset?alias=personal", handler: svc.DeviceResetHandler()},
		{name: "pending", method: http.MethodGet, path: "/outlook/auth/pending", handler: svc.PendingListHandler()},
		{name: "pending clear", method: http.MethodPost, path: "/outlook/auth/pending/clear", handler: svc.PendingClearHandler()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, test.path, nil).WithContext(identityContext)
			rec := httptest.NewRecorder()
			test.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body %q", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), graph.IdentityNamespaceRequiredMessage) {
				t.Fatalf("unexpected response body: %q", rec.Body.String())
			}
		})
	}
}

func TestCustomAuthEndpointRejectsNonIdentityBearer(t *testing.T) {
	svc := NewService(&Config{SecretsBase: t.TempDir()})
	headers := []string{
		"Basic dXNlcjpwYXNz",
		"Bearer opaque-token",
		"Bearer " + testJWT(t, map[string]any{"aud": "outlook"}),
	}
	for _, header := range headers {
		t.Run(header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/outlook/auth/pending", nil)
			req.Header.Set("Authorization", header)
			rec := httptest.NewRecorder()
			svc.PendingListHandler().ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d body %q", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "opaque-token") || strings.Contains(rec.Body.String(), "aud") {
				t.Fatalf("response leaked token or claim details: %q", rec.Body.String())
			}
		})
	}
}

func TestPendingEndpointsUseBearerIdentityAndIgnoreNamespaceParameter(t *testing.T) {
	svc := NewService(&Config{SecretsBase: t.TempDir()})
	svc.pending.Put(&PendingAuth{UUID: "alice-session", Alias: "personal", TenantID: "common", Namespace: "alice@example.com", ExpiresAt: time.Now().Add(time.Hour)})
	svc.pending.Put(&PendingAuth{UUID: "bob-session", Alias: "personal", TenantID: "common", Namespace: "bob@example.com", ExpiresAt: time.Now().Add(time.Hour)})
	aliceBearer := "Bearer " + testJWT(t, map[string]any{"email": "alice@example.com"})

	listReq := httptest.NewRequest(http.MethodGet, "/outlook/auth/pending?namespace=bob@example.com", nil)
	listReq.Header.Set("Authorization", aliceBearer)
	listRec := httptest.NewRecorder()
	svc.PendingListHandler().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d body %q", listRec.Code, listRec.Body.String())
	}
	var rows []struct {
		UUID      string
		Namespace string
	}
	if err := json.NewDecoder(listRec.Body).Decode(&rows); err != nil {
		t.Fatalf("failed to decode pending list: %v", err)
	}
	if len(rows) != 1 || rows[0].UUID != "alice-session" || rows[0].Namespace != "alice@example.com" {
		t.Fatalf("query namespace overrode bearer identity: %#v", rows)
	}

	clearReq := httptest.NewRequest(http.MethodPost, "/outlook/auth/pending/clear?namespace=bob@example.com", nil)
	clearReq.Header.Set("Authorization", aliceBearer)
	clearRec := httptest.NewRecorder()
	svc.PendingClearHandler().ServeHTTP(clearRec, clearReq)
	if clearRec.Code != http.StatusOK {
		t.Fatalf("clear status = %d body %q", clearRec.Code, clearRec.Body.String())
	}
	if got := svc.pending.ListNamespace("alice@example.com"); len(got) != 0 {
		t.Fatalf("alice pending sessions were not cleared: %#v", got)
	}
	if got := svc.pending.ListNamespace("bob@example.com"); len(got) != 1 || got[0].UUID != "bob-session" {
		t.Fatalf("bob pending sessions were unexpectedly changed: %#v", got)
	}
}

func TestDeviceHandlerUsesPendingUUIDWithoutBearer(t *testing.T) {
	svc := NewService(&Config{SecretsBase: t.TempDir()})
	svc.pending.Put(&PendingAuth{
		UUID:      "device-session",
		Alias:     "personal",
		TenantID:  "common",
		Namespace: "alice@example.com",
		Status:    AuthStatusWaitingForUser,
		Message:   "Open https://microsoft.com/devicelogin and enter code ABC-123",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	req := httptest.NewRequest(http.MethodGet, "/outlook/auth/device/device-session", nil)
	rec := httptest.NewRecorder()
	svc.DeviceHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected device page without bearer, got %d body %q", rec.Code, rec.Body.String())
	}
}
