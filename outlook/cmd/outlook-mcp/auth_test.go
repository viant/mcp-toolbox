package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/viant/mcp-protocol/authorization"
)

func TestPassiveBearerAuthorizerInjectsAuthorizationToken(t *testing.T) {
	var got string
	next := passiveBearerAuthorizer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := r.Context().Value(authorization.TokenKey).(*authorization.Token)
		if ok && token != nil {
			got = token.Token
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	next.ServeHTTP(httptest.NewRecorder(), req)

	if got != "Bearer test-token" {
		t.Fatalf("unexpected token: got %q want %q", got, "Bearer test-token")
	}
}

func TestPassiveBearerAuthorizerAllowsMissingAuthorization(t *testing.T) {
	called := false
	next := passiveBearerAuthorizer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if token := r.Context().Value(authorization.TokenKey); token != nil {
			t.Fatalf("unexpected auth token in context: %v", token)
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	next.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if !called {
		t.Fatal("expected next handler to be called")
	}
}
