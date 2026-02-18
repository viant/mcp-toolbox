package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJiraTokenIngestAndCheck(t *testing.T) {
	svc := NewService(&Config{CallbackBaseURL: "http://localhost:7777"})
	mux := http.NewServeMux()
	svc.RegisterHTTP(mux)

	// Basic auth ingest
	req := httptest.NewRequest(http.MethodPost, "/jira/auth/token?alias=a1&domain=viantinc.atlassian.net", nil)
	cred := base64.StdEncoding.EncodeToString([]byte("user@example.com:tok123"))
	req.Header.Set("Authorization", "Basic "+cred)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("basic ingest status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Check token
	req = httptest.NewRequest(http.MethodGet, "/jira/auth/check?alias=a1&domain=viantinc.atlassian.net", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("check status=%d body=%s", rr.Code, rr.Body.String())
	}
	var chk map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &chk)
	if chk["hasToken"] != true {
		t.Fatalf("expected hasToken true, got %#v", chk)
	}
}

func TestJiraTokenIngestJSON(t *testing.T) {
	svc := NewService(&Config{CallbackBaseURL: "http://localhost:7777"})
	mux := http.NewServeMux()
	svc.RegisterHTTP(mux)

	body := map[string]any{
		"alias":        "b1",
		"domain":       "https://viantinc.atlassian.net",
		"email":        "user@example.com",
		"access_token": "tok456",
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/jira/auth/token", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("json ingest status=%d body=%s", rr.Code, rr.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/jira/auth/check?alias=b1&domain=viantinc.atlassian.net", nil)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("check status=%d body=%s", rr.Code, rr.Body.String())
	}
	var chk map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &chk)
	if chk["hasToken"] != true {
		t.Fatalf("expected hasToken true, got %#v", chk)
	}
}
