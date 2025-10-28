package service

import (
    "bytes"
    "context"
    "encoding/base64"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func newTestService(t *testing.T) *Service {
    t.Helper()
    dir := t.TempDir()
    svc := NewService(&Config{ClientID: "test-client", StorageDir: dir, CallbackBaseURL: "http://localhost:8080"})
    return svc
}

func Test_tokenKey(t *testing.T) {
    svc := newTestService(t)
    if got := svc.tokenKey("ns1", "a", ""); got != "ns1|a|github.com" {
        t.Fatalf("unexpected token key: %s", got)
    }
    if got := svc.tokenKey("ns1", "b", "gh.myhost:8443/sub"); got != "ns1|b|gh.myhost:8443/sub" {
        t.Fatalf("unexpected token key with domain: %s", got)
    }
}

func Test_save_load_clear_Token(t *testing.T) {
    svc := newTestService(t)
    alias, domain, token := "acc", "", "tok-123"

    if got := svc.loadToken("default", alias, domain); got != "" {
        t.Fatalf("expected empty token before save, got %q", got)
    }

    // save caches in-memory only
    svc.saveToken("default", alias, domain, token)

    // load should return the cached value
    if got := svc.loadToken("default", alias, domain); got != token {
        t.Fatalf("loadToken mismatch, got %q want %q", got, token)
    }

    // clear should drop cache
    svc.clearToken("default", alias, domain)
    if got := svc.loadToken("default", alias, domain); got != "" {
        t.Fatalf("expected empty after clear, got %q", got)
    }
}

func Test_parseAuthHeaderToken(t *testing.T) {
    if got := parseAuthHeaderToken("Bearer abc123"); got != "abc123" {
        t.Fatalf("bearer parse mismatch: %q", got)
    }
    basic := base64.StdEncoding.EncodeToString([]byte("user:secrettoken"))
    if got := parseAuthHeaderToken("Basic " + basic); got != "secrettoken" {
        t.Fatalf("basic parse mismatch: %q", got)
    }
    basic2 := base64.StdEncoding.EncodeToString([]byte("justtoken"))
    if got := parseAuthHeaderToken("Basic " + basic2); got != "justtoken" {
        t.Fatalf("basic (no colon) parse mismatch: %q", got)
    }
    if got := parseAuthHeaderToken("Foo bar"); got != "" {
        t.Fatalf("expected empty for unknown scheme, got %q", got)
    }
}

func Test_DeviceHandler(t *testing.T) {
    svc := newTestService(t)
    pend := &PendingAuth{UUID: "u1", Alias: "acc", Namespace: "ns1", UserCode: "CODE123", VerifyURL: "https://example.com/verify"}
    svc.pending.Put(pend)

    rr := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/github/auth/device/u1", nil)
    svc.DeviceHandler().ServeHTTP(rr, req)

    if rr.Code != http.StatusOK {
        t.Fatalf("unexpected status: %d", rr.Code)
    }
    if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
        t.Fatalf("unexpected content type: %s", ct)
    }
    body := rr.Body.String()
    if !strings.Contains(body, "CODE123") || !strings.Contains(body, "https://example.com/verify") {
        t.Fatalf("device page missing expected content: %s", body)
    }

    // invalid path
    rr = httptest.NewRecorder()
    req = httptest.NewRequest(http.MethodGet, "/github/auth/device/", nil)
    svc.DeviceHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusBadRequest {
        t.Fatalf("expected 400 for invalid path, got %d", rr.Code)
    }

    // not found
    rr = httptest.NewRecorder()
    req = httptest.NewRequest(http.MethodGet, "/github/auth/device/unknown", nil)
    svc.DeviceHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusNotFound {
        t.Fatalf("expected 404 for missing uuid, got %d", rr.Code)
    }
}

func Test_PendingList_and_Clear_Handlers(t *testing.T) {
    svc := newTestService(t)
    svc.pending.Put(&PendingAuth{UUID: "a1", Alias: "accA", Namespace: "nsX", UserCode: "C1", VerifyURL: "U1"})
    svc.pending.Put(&PendingAuth{UUID: "a2", Alias: "accB", Namespace: "nsX", UserCode: "C2", VerifyURL: "U2"})

    // list
    rr := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/github/auth/pending?namespace=nsX", nil)
    svc.PendingListHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("list status: %d", rr.Code)
    }
    var rows []map[string]string
    if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
        t.Fatalf("failed to decode list json: %v", err)
    }
    if len(rows) != 2 {
        t.Fatalf("expected 2 rows, got %d", len(rows))
    }

    // method not allowed
    rr = httptest.NewRecorder()
    req = httptest.NewRequest(http.MethodPost, "/github/auth/pending?namespace=nsX", nil)
    svc.PendingListHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusMethodNotAllowed {
        t.Fatalf("expected 405 for wrong method, got %d", rr.Code)
    }

    // clear
    rr = httptest.NewRecorder()
    req = httptest.NewRequest(http.MethodPost, "/github/auth/pending/clear?namespace=nsX", nil)
    svc.PendingClearHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("clear status: %d", rr.Code)
    }
    var cleared struct{ Cleared int `json:"cleared"` }
    _ = json.Unmarshal(rr.Body.Bytes(), &cleared)
    if cleared.Cleared != 2 {
        t.Fatalf("expected cleared=2 got %d", cleared.Cleared)
    }

    // verify list empty
    rr = httptest.NewRecorder()
    req = httptest.NewRequest(http.MethodGet, "/github/auth/pending?namespace=nsX", nil)
    svc.PendingListHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("list-after-clear status: %d", rr.Code)
    }
    _ = json.Unmarshal(rr.Body.Bytes(), &rows)
    if len(rows) != 0 {
        t.Fatalf("expected 0 rows after clear, got %d", len(rows))
    }
}

func Test_TokenIngestHandler(t *testing.T) {
    svc := newTestService(t)

    // wrong method
    rr := httptest.NewRecorder()
    req := httptest.NewRequest(http.MethodGet, "/github/auth/token?alias=a", nil)
    svc.TokenIngestHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusMethodNotAllowed {
        t.Fatalf("expected 405, got %d", rr.Code)
    }

    // missing alias
    rr = httptest.NewRecorder()
    req = httptest.NewRequest(http.MethodPost, "/github/auth/token", nil)
    svc.TokenIngestHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusBadRequest {
        t.Fatalf("expected 400 for missing alias, got %d", rr.Code)
    }

    // bearer header
    rr = httptest.NewRecorder()
    req = httptest.NewRequest(http.MethodPost, "/github/auth/token?alias=a1&domain=github.com", nil)
    req.Header.Set("Authorization", "Bearer ZZZ")
    svc.TokenIngestHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d", rr.Code)
    }
    if tok := svc.loadToken("default", "a1", "github.com"); tok != "ZZZ" {
        t.Fatalf("expected saved token ZZZ, got %q", tok)
    }

    // json body along with Authorization header (Basic), as the handler expects token either in header or body
    rr = httptest.NewRecorder()
    body := map[string]string{"alias": "b1", "domain": "gh.myhost:8443", "access_token": "TTT"}
    b, _ := json.Marshal(body)
    req = httptest.NewRequest(http.MethodPost, "/github/auth/token?alias=b1", bytes.NewReader(b))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("ignored:TTT")))
    svc.TokenIngestHandler().ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("expected 200, got %d", rr.Code)
    }
    // with JSON body, domain is picked from payload
    if tok := svc.loadToken("default", "b1", "gh.myhost:8443"); tok != "TTT" {
        t.Fatalf("expected saved token TTT under provided domain, got %q", tok)
    }
}

func Test_Credential_ReturnsSavedToken(t *testing.T) {
    svc := newTestService(t)
    svc.saveToken("default", "acc", "", "SAVED")
    got, err := svc.Credential(context.Background(), "acc", "", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if got != "SAVED" {
        t.Fatalf("expected saved token, got %q", got)
    }
}

func Test_RegisterHTTP_routes(t *testing.T) {
    svc := newTestService(t)
    mux := http.NewServeMux()
    svc.RegisterHTTP(mux)

    // ensure handlers respond
    tests := []struct{ method, path string; body io.Reader; want int }{
        {http.MethodGet, "/github/auth/device/x", nil, http.StatusNotFound},
        {http.MethodGet, "/github/auth/pending?namespace=default", nil, http.StatusOK},
        {http.MethodPost, "/github/auth/pending/clear?namespace=default", nil, http.StatusOK},
        {http.MethodPost, "/github/auth/token?alias=a", nil, http.StatusBadRequest},
    }
    for _, tc := range tests {
        rr := httptest.NewRecorder()
        req := httptest.NewRequest(tc.method, tc.path, tc.body)
        mux.ServeHTTP(rr, req)
        if rr.Code != tc.want {
            t.Fatalf("%s %s => %d want %d", tc.method, tc.path, rr.Code, tc.want)
        }
    }
}
