package mcp

import (
    "context"
    "encoding/json"
    "fmt"
    "html"
    "net/http"
    "regexp"
    "strings"
    "time"

    protoclient "github.com/viant/mcp-protocol/client"

    "github.com/Azure/azure-sdk-for-go/sdk/azidentity"
    oa "github.com/viant/mcp-toolbox/auth"
    "github.com/viant/mcp-toolbox/outlook/graph"
    "github.com/viant/scy"
    "github.com/viant/scy/cred"
    "sync"
)

// Service wires graph manager and optional UI/secret helpers.
type Service struct {
    graphMgr *graph.Manager
    baseURL  string
    // ui/secrets can be added when we introduce OOB UI forms later.
    useText    bool
    pending    *PendingAuths
    auth       *oa.Service
    azure      *cred.Azure
    tenantID   string
    clientID   string
    storageDir string

    // service-level lazy cache of DeviceCodeCredential per namespace+alias
    credMu sync.RWMutex
    creds  map[string]*azidentity.DeviceCodeCredential
}

func NewService(cfg *Config) *Service {
	if cfg == nil {
		cfg = &Config{}
	}
	useText := !cfg.UseData
	// Optionally resolve Azure OAuth2 client from scy EncodedResource.
	var az *cred.Azure
	if cfg.AzureRef != "" {
		// Decode EncodedResource and load with scy.
		res := cfg.AzureRef.Decode(context.Background(), cred.Azure{})
		if sec, err := scy.New().Load(context.Background(), res); err == nil {
			if v, ok := sec.Target.(*cred.Azure); ok {
				az = v
			}
		}
	}

	clientID := cfg.ClientID
	if az != nil && az.ClientID != "" {
		clientID = az.ClientID
	}
	tenantID := cfg.TenantID

	// Reuse SQLKit interaction UI helpers to keep elicitation patterns consistent.
    return &Service{
        graphMgr:   graph.NewManager(clientID, cfg.StorageDir),
        baseURL:    cfg.CallbackBaseURL,
        useText:    useText,
        pending:    NewPendingAuths(),
        auth:       oa.New(),
        azure:      az,
        tenantID:   tenantID,
        clientID:   clientID,
        storageDir: cfg.StorageDir,
        creds:      map[string]*azidentity.DeviceCodeCredential{},
    }
}

func (s *Service) RegisterHTTP(mux *http.ServeMux) {
	// Device code display endpoint – shows code for a pending login.
	mux.HandleFunc("/outlook/auth/device/", s.DeviceHandler())
	// List/clear pending endpoints
	mux.HandleFunc("/outlook/auth/pending", s.PendingListHandler())
	mux.HandleFunc("/outlook/auth/pending/clear", s.PendingClearHandler())
}

// DeviceHandler serves the device login page for a pending auth UUID.
func (s *Service) DeviceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// URL: /outlook/auth/device/{uuid}?alias=...&elicitationId=...
		path := r.URL.Path
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) != 4 { // outlook auth device {uuid}
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		uuid := parts[3]
		pend, ok := s.pending.Get(uuid)
		if !ok {
			http.Error(w, "no pending auth", http.StatusNotFound)
			return
		}
		msg := s.graphMgr.DevicePrompt(pend.Alias)
		if msg == "" {
			deadline := time.Now().Add(8 * time.Second)
			for msg == "" && time.Now().Before(deadline) {
				time.Sleep(200 * time.Millisecond)
				msg = s.graphMgr.DevicePrompt(pend.Alias)
			}
		}
		if msg == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, buildWaitingForDeviceHTML())
			return
		}
		// Render a clickable link and highlight the code for easier UX.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, buildDeviceLoginHTML(msg))
	}
}

// buildDeviceLoginHTML converts the Azure device prompt into a clickable HTML with copyable code.
func buildDeviceLoginHTML(msg string) string {
	url := "https://microsoft.com/devicelogin"
	code := ""
	// Extract first URL
	if m := regexp.MustCompile(`https?://[^\s]+`).FindString(msg); m != "" {
		url = m
	}
	// Extract code (case-insensitive "code <VALUE>") allowing hyphens
	if m := regexp.MustCompile(`(?i)code\s+([A-Z0-9-]+)`).FindStringSubmatch(msg); len(m) == 2 {
		code = m[1]
	}
	escURL := html.EscapeString(url)
	escCode := html.EscapeString(code)
	// Fallback rendering if we couldn't parse a code
	if escCode == "" {
		escMsg := html.EscapeString(msg)
		return fmt.Sprintf(`<html><body>
<h3>Sign in to Outlook</h3>
<p>Open <a href="%[1]s" target="_blank" rel="noopener noreferrer">%[1]s</a> and follow the instructions.</p>
<pre>%[2]s</pre>
<p>Keep this tab open; return to your assistant after completing sign-in.</p>
</body></html>`, escURL, escMsg)
	}
	return fmt.Sprintf(`<html><body style="font-family: -apple-system, Segoe UI, Roboto, sans-serif;">
<h3>Sign in to Outlook</h3>
<p>Click to open: <a href="%[1]s" target="_blank" rel="noopener noreferrer">%[1]s</a></p>
<p>Then enter this code:</p>
<p style="font-size: 1.4em; font-weight: 600;"><code>%[2]s</code> <button onclick="navigator.clipboard.writeText('%[3]s')">Copy</button></p>
<p>Keep this tab open; return to your assistant after completing sign-in.</p>
</body></html>`, escURL, escCode, escCode)
}

func buildWaitingForDeviceHTML() string {
	url := html.EscapeString("https://microsoft.com/devicelogin")
	return fmt.Sprintf(`<!doctype html>
<html><head>
<meta http-equiv="refresh" content="2">
<meta charset="utf-8">
<title>Sign in to Outlook</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:24px}</style>
</head><body>
<h3>Sign in to Outlook</h3>
<p>Preparing device login… this page refreshes automatically.</p>
<p>If it takes too long, you can open <a href="%[1]s" target="_blank" rel="noopener noreferrer">%[1]s</a> and follow the instructions.</p>
<p>Keep this tab open; return to your assistant after completing sign-in.</p>
</body></html>`, url)
}

// PendingListHandler returns JSON of pending auths for a namespace.
func (s *Service) PendingListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			if v, err := s.auth.Namespace(r.Context()); err == nil {
				ns = v
			}
		}
		if ns == "" {
			http.Error(w, "namespace required", http.StatusBadRequest)
			return
		}
		list := s.pending.ListNamespace(ns)
		type row struct{ UUID, Alias, TenantID, Namespace string }
		out := make([]row, 0, len(list))
		for _, v := range list {
			out = append(out, row{UUID: v.UUID, Alias: v.Alias, TenantID: v.TenantID, Namespace: v.Namespace})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// PendingClearHandler clears all pending auths for a namespace.
func (s *Service) PendingClearHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ns := r.URL.Query().Get("namespace")
		if ns == "" {
			if v, err := s.auth.Namespace(r.Context()); err == nil {
				ns = v
			}
		}
		if ns == "" {
			http.Error(w, "namespace required", http.StatusBadRequest)
			return
		}
		cleared := s.pending.ClearNamespace(ns)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"cleared": len(cleared), "uuids": cleared})
	}
}

func (s *Service) GraphManager() *graph.Manager { return s.graphMgr }
func (s *Service) UseTextField() bool           { return s.useText }
func (s *Service) BaseURL() string              { return s.baseURL }
func (s *Service) Pending() *PendingAuths       { return s.pending }
func (s *Service) Auth() *oa.Service            { return s.auth }
func (s *Service) TenantID() string             { return s.tenantID }
func (s *Service) ClientID() string             { return s.clientID }
func (s *Service) StorageDir() string           { return s.storageDir }

// NewOperationsHook allows passing protocol client operations if needed later.
func (s *Service) NewOperationsHook(_ protoclient.Operations) {}

// Credential returns an azidentity.DeviceCodeCredential cached per account alias.
// It delegates acquisition to the graph manager on cache miss and stores it until process restart.
func (s *Service) Credential(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*azidentity.DeviceCodeCredential, error) {
    ns, _ := s.auth.Namespace(ctx)
    if ns == "" { ns = "default" }
    key := ns + "|" + alias
    s.credMu.RLock()
    if c := s.creds[key]; c != nil {
        s.credMu.RUnlock()
        return c, nil
    }
    s.credMu.RUnlock()
    cred, err := s.graphMgr.Credential(ctx, alias, tenantID, scopes, prompt)
    if err != nil {
        return nil, err
    }
    s.credMu.Lock()
    if existing := s.creds[key]; existing != nil {
        s.credMu.Unlock()
        return existing, nil
    }
    s.creds[key] = cred
    s.credMu.Unlock()
    return cred, nil
}
