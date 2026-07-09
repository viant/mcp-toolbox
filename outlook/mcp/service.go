package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	protoclient "github.com/viant/mcp-protocol/client"

	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	afsscratchpad "github.com/viant/afs/scratchpad"
	oa "github.com/viant/mcp-toolbox/auth"
	"github.com/viant/mcp-toolbox/outlook/graph"
	nsprov "github.com/viant/mcp/server/namespace"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
)

// Service wires graph manager and optional UI/secret helpers.
type Service struct {
	graphMgr *graph.Manager
	baseURL  string
	// ui/secrets can be added when we introduce OOB UI forms later.
	useText          bool
	pending          *PendingAuths
	auth             *oa.Service
	ns               *nsprov.DefaultProvider
	azure            *cred.Azure
	tenantID         string
	clientID         string
	secretsBase      string
	scratchpadUserID string

	// service-level lazy cache of DeviceCodeCredential per namespace+alias
	credMu sync.RWMutex
	creds  map[string]*azidentity.DeviceCodeCredential

	// Elicitation dedupe per session and globally (alias+tenant)
	elicitMu       sync.Mutex
	elicited       map[string]time.Time
	elicitedGlobal map[string]time.Time
	tunCoolOnce    sync.Once
	tunCooldown    time.Duration
}

const authSessionTTL = 15 * time.Minute

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
	graph.ConfigureAttachmentSources(graph.AttachmentSourceConfig{
		AllowedSourceSchemes: cfg.AttachmentSourceSchemes,
	})
	namespaceClaimKeys := NormalizeNamespaceClaimKeys(cfg.NamespaceClaimKeys)

	// Reuse SQLKit interaction UI helpers to keep elicitation patterns consistent.
	s := &Service{
		graphMgr:         graph.NewManagerWithNamespaceClaimKeys(clientID, cfg.SecretsBase, namespaceClaimKeys),
		baseURL:          cfg.CallbackBaseURL,
		useText:          useText,
		pending:          NewPendingAuths(),
		auth:             oa.New(),
		azure:            az,
		tenantID:         tenantID,
		clientID:         clientID,
		secretsBase:      cfg.SecretsBase,
		scratchpadUserID: strings.TrimSpace(cfg.ScratchpadUserID),
		creds:            map[string]*azidentity.DeviceCodeCredential{},
		elicited:         map[string]time.Time{},
		elicitedGlobal:   map[string]time.Time{},
	}
	s.ns = nsprov.NewProvider(&nsprov.Config{PreferIdentity: true, ClaimKeys: namespaceClaimKeys, Hash: nsprov.HashConfig{Algorithm: "md5", Prefix: "tkn-"}, Path: nsprov.PathConfig{Prefix: "id-", Sanitize: true, MaxLen: 120}})
	if strings.TrimSpace(cfg.ScratchpadRootURI) != "" || strings.TrimSpace(cfg.ScratchpadUserID) != "" {
		afsscratchpad.Register(
			afsscratchpad.WithRootURI(cfg.ScratchpadRootURI),
			afsscratchpad.WithUserIDProvider(s.scratchpadUserIDFromContext),
			afsscratchpad.WithUserID(s.scratchpadUserID),
			afsscratchpad.WithAllowedTargetSchemes(cfg.ScratchpadTargetSchemes...),
		)
	}
	return s
}

func (s *Service) RegisterHTTP(mux *http.ServeMux) {
	// Device code display endpoint – shows code for a pending login.
	mux.HandleFunc("/outlook/auth/device/", s.DeviceHandler())
	// List/clear pending endpoints
	mux.HandleFunc("/outlook/auth/pending", s.PendingListHandler())
	mux.HandleFunc("/outlook/auth/pending/clear", s.PendingClearHandler())
	// Start/check endpoints to align with GitHub-style OOB
	mux.HandleFunc("/outlook/auth/start", s.DeviceStartHandler())
	mux.HandleFunc("/outlook/auth/check", s.DeviceCheckHandler())
	mux.HandleFunc("/outlook/auth/reset", s.DeviceResetHandler())
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
			http.Error(w, "unknown Outlook sign-in session", http.StatusNotFound)
			return
		}
		if pend.Status == AuthStatusWaitingForCode && pend.Message == "" {
			deadline := time.Now().Add(8 * time.Second)
			for pend.Message == "" && pend.Error == "" && pend.Status == AuthStatusWaitingForCode && time.Now().Before(deadline) {
				time.Sleep(200 * time.Millisecond)
				if next, ok := s.pending.Get(uuid); ok {
					pend = next
				}
			}
		}
		if pend.Status == AuthStatusAuthenticated {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, buildDeviceLoginSuccessHTML())
			return
		}
		if pend.Status == AuthStatusExpired {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, buildDeviceLoginErrorHTML("The Outlook sign-in session expired. Start sign-in again."))
			return
		}
		if pend.Status == AuthStatusCanceled {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, buildDeviceLoginErrorHTML("The Outlook sign-in session was canceled."))
			return
		}
		if pend.Status == AuthStatusFailed || pend.Error != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, buildDeviceLoginErrorHTML(pend.Error))
			return
		}
		if pend.Message == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprint(w, buildWaitingForDeviceHTML())
			return
		}
		// Render a clickable link and highlight the code for easier UX.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, buildDeviceLoginHTML(pend.Message))
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

func buildDeviceLoginErrorHTML(message string) string {
	if strings.TrimSpace(message) == "" {
		message = "Outlook sign-in failed."
	}
	escMessage := html.EscapeString(message)
	return fmt.Sprintf(`<!doctype html>
<html><head>
<meta charset="utf-8">
<title>Outlook sign-in failed</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;line-height:1.45}pre{white-space:pre-wrap;background:#f6f8fa;padding:12px;border-radius:6px}</style>
</head><body>
<h3>Outlook sign-in failed</h3>
<p>The device login did not start successfully.</p>
<pre>%[1]s</pre>
<p>Check the Azure app registration settings, then start sign-in again.</p>
</body></html>`, escMessage)
}

func buildDeviceLoginSuccessHTML() string {
	return `<!doctype html>
<html><head>
<meta charset="utf-8">
<title>Outlook sign-in complete</title>
<style>body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;line-height:1.45}</style>
</head><body>
<h3>Outlook sign-in complete</h3>
<p>You can return to your assistant.</p>
</body></html>`
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

// DeviceStartHandler starts device login for alias and returns a uuid and OOB URL.
func (s *Service) DeviceStartHandler() http.HandlerFunc {
	type out struct {
		UUID      string     `json:"uuid"`
		OOBUrl    string     `json:"oobUrl"`
		Status    AuthStatus `json:"status"`
		HasToken  bool       `json:"hasToken"`
		ExpiresAt time.Time  `json:"expiresAt,omitempty"`
		Error     string     `json:"error,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		alias := r.URL.Query().Get("alias")
		tenant := s.normalizeTenant(r.URL.Query().Get("tenant"))
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
			return
		}
		scopes := graph.DefaultScopes()
		check := s.graphMgr.AuthCheck(r.Context(), alias, tenant, scopes)
		if check.Status == graph.AuthCheckTransient {
			http.Error(w, graph.UserMessageForAuthError(check.Err), http.StatusServiceUnavailable)
			return
		}
		if check.Status == graph.AuthCheckFailed {
			message := graph.UserMessageForAuthError(check.Err)
			if message == "" {
				message = "Outlook authentication check failed"
			}
			http.Error(w, message, http.StatusInternalServerError)
			return
		}
		var session *PendingAuth
		if check.Status == graph.AuthCheckReady {
			session = s.completedAuthSession(r.Context(), alias, tenant, scopes)
		} else {
			session = s.startAuthSession(r.Context(), alias, tenant, scopes)
		}
		oob := s.authSessionURL(session)
		if r.Method == http.MethodGet {
			http.Redirect(w, r, oob, http.StatusTemporaryRedirect)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out{
			UUID:      session.UUID,
			OOBUrl:    oob,
			Status:    session.Status,
			HasToken:  session.Status == AuthStatusAuthenticated,
			ExpiresAt: session.ExpiresAt,
			Error:     session.Error,
		})
	}
}

// DeviceCheckHandler returns whether a credential is available for alias/tenant in current namespace.
func (s *Service) DeviceCheckHandler() http.HandlerFunc {
	type out struct{ HasToken bool }
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		alias := r.URL.Query().Get("alias")
		tenant := s.normalizeTenant(r.URL.Query().Get("tenant"))
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
			return
		}
		has := s.graphMgr.AuthCheck(r.Context(), alias, tenant, graph.DefaultScopes()).Status == graph.AuthCheckReady
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out{HasToken: has})
	}
}

// DeviceResetHandler clears local auth state for an account alias.
func (s *Service) DeviceResetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		alias := r.URL.Query().Get("alias")
		tenant := s.normalizeTenant(r.URL.Query().Get("tenant"))
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
			return
		}
		d, _ := s.ns.Namespace(r.Context())
		ns := d.Name
		if ns == "" {
			ns = "default"
		}
		purge := parseBool(r.URL.Query().Get("purge"))
		result, err := s.graphMgr.ResetAuth(r.Context(), alias, tenant, graph.DefaultScopes(), purge)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s.credMu.Lock()
		prefix := ns + "|" + alias + "|" + tenant + "|"
		for key := range s.creds {
			if strings.HasPrefix(key, prefix) {
				result.ClearedMemory = true
				delete(s.creds, key)
			}
		}
		s.credMu.Unlock()
		clearedPending := s.pending.ClearAlias(ns, alias)
		out := struct {
			graph.ResetResult
			ClearedPending []string `json:"clearedPending,omitempty"`
		}{ResetResult: result, ClearedPending: clearedPending}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	default:
		return false
	}
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
			if d, err := s.ns.Namespace(r.Context()); err == nil {
				ns = d.Name
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
			if d, err := s.ns.Namespace(r.Context()); err == nil {
				ns = d.Name
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
func (s *Service) SecretsBase() string          { return s.secretsBase }

// NewOperationsHook allows passing protocol client operations if needed later.
func (s *Service) NewOperationsHook(_ protoclient.Operations) {}

// Credential returns an azidentity.DeviceCodeCredential cached per account alias.
// It delegates acquisition to the graph manager on cache miss and stores it until process restart.
func (s *Service) Credential(ctx context.Context, alias, tenantID string, scopes []string, prompt func(string)) (*azidentity.DeviceCodeCredential, error) {
	tenantID = s.normalizeTenant(tenantID)
	dsc, _ := s.ns.Namespace(ctx)
	ns := dsc.Name
	if ns == "" {
		ns = "default"
	}
	key := authSessionKey(ns, alias, tenantID, scopes)
	s.credMu.RLock()
	if c := s.creds[key]; c != nil {
		s.credMu.RUnlock()
		return c, nil
	}
	s.credMu.RUnlock()
	// Wrap prompt with elicitation cooldown/dedupe
	wp := prompt
	if prompt != nil {
		wp = func(msg string) { s.maybeElicitOnce(ctx, alias, tenantID, msg, prompt) }
	}
	cred, err := s.graphMgr.Credential(ctx, alias, tenantID, scopes, wp)
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
	// Clear dedupe marks after successful acquisition
	s.clearElicitedAll(alias, tenantID)
	return cred, nil
}

func (s *Service) namespace(ctx context.Context) string {
	d, _ := s.ns.Namespace(ctx)
	if d.Name != "" {
		return d.Name
	}
	return "default"
}

func (s *Service) scratchpadUserIDFromContext(ctx context.Context) string {
	if s != nil && s.ns != nil {
		if d, err := s.ns.Namespace(ctx); err == nil && !d.IsDefault && strings.TrimSpace(d.Name) != "" {
			return strings.TrimSpace(d.Name)
		}
	}
	if s == nil {
		return ""
	}
	return strings.TrimSpace(s.scratchpadUserID)
}

func (s *Service) withScratchpadUser(ctx context.Context) context.Context {
	userID := s.scratchpadUserIDFromContext(ctx)
	if userID == "" {
		return ctx
	}
	return afsscratchpad.ContextWithUserID(ctx, userID)
}

func (s *Service) normalizeTenant(tenant string) string {
	if strings.TrimSpace(tenant) != "" {
		return tenant
	}
	return s.tenantID
}

func (s *Service) authSessionURL(session *PendingAuth) string {
	if session == nil {
		return ""
	}
	base := strings.TrimRight(s.baseURL, "/")
	return fmt.Sprintf("%s/outlook/auth/device/%s?alias=%s", base, session.UUID, session.Alias)
}

func (s *Service) completedAuthSession(ctx context.Context, alias, tenant string, scopes []string) *PendingAuth {
	tenant = s.normalizeTenant(tenant)
	ns := s.namespace(ctx)
	session, _ := s.pending.GetOrCreate(ns, alias, tenant, scopes, time.Minute, newUUID)
	if session.Status != AuthStatusAuthenticated {
		s.pending.Complete(session.UUID)
		session, _ = s.pending.Get(session.UUID)
	}
	return session
}

func (s *Service) startAuthSession(ctx context.Context, alias, tenant string, scopes []string) *PendingAuth {
	start := time.Now()
	tenant = s.normalizeTenant(tenant)
	ns := s.namespace(ctx)
	debugf("startAuthSession ns=%q alias=%q tenant=%q deadline_in=%s", ns, alias, tenant, debugDeadline(ctx))
	session, created := s.pending.GetOrCreate(ns, alias, tenant, scopes, authSessionTTL, newUUID)
	if !created {
		debugf("startAuthSession ns=%q alias=%q tenant=%q existing session=%q status=%q elapsed=%s", ns, alias, tenant, session.UUID, session.Status, time.Since(start).Round(time.Millisecond))
		return session
	}
	debugf("startAuthSession ns=%q alias=%q tenant=%q created session=%q elapsed=%s", ns, alias, tenant, session.UUID, time.Since(start).Round(time.Millisecond))
	authCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), authSessionTTL)
	go func(uuid string) {
		bgStart := time.Now()
		debugf("authSession background_start session=%q ns=%q alias=%q tenant=%q ttl=%s", uuid, ns, alias, tenant, authSessionTTL)
		defer cancel()
		_, err := s.graphMgr.Credential(authCtx, alias, tenant, scopes, func(msg string) {
			debugf("authSession prompt session=%q ns=%q alias=%q tenant=%q message_len=%d elapsed=%s", uuid, ns, alias, tenant, len(msg), time.Since(bgStart).Round(time.Millisecond))
			s.pending.SetMessage(uuid, msg)
		})
		if err != nil {
			if graph.IsTransientAuthProviderError(err) && authCtx.Err() == nil {
				message := graph.UserMessageForAuthError(err)
				debugf("authSession failed_transient session=%q ns=%q alias=%q tenant=%q err=%v message=%q elapsed=%s", uuid, ns, alias, tenant, err, message, time.Since(bgStart).Round(time.Millisecond))
				s.pending.Fail(uuid, message)
				return
			}
			if authCtx.Err() != nil && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
				debugf("authSession expired session=%q ns=%q alias=%q tenant=%q err=%v elapsed=%s", uuid, ns, alias, tenant, err, time.Since(bgStart).Round(time.Millisecond))
				s.pending.Expire(uuid)
				return
			}
			if graph.IsTransientAuthProviderError(err) {
				message := graph.UserMessageForAuthError(err)
				debugf("authSession failed_transient session=%q ns=%q alias=%q tenant=%q err=%v message=%q elapsed=%s", uuid, ns, alias, tenant, err, message, time.Since(bgStart).Round(time.Millisecond))
				s.pending.Fail(uuid, message)
				return
			}
			debugf("authSession failed session=%q ns=%q alias=%q tenant=%q err=%v elapsed=%s", uuid, ns, alias, tenant, err, time.Since(bgStart).Round(time.Millisecond))
			s.pending.Fail(uuid, err.Error())
			return
		}
		debugf("authSession authenticated session=%q ns=%q alias=%q tenant=%q elapsed=%s", uuid, ns, alias, tenant, time.Since(bgStart).Round(time.Millisecond))
		s.pending.Complete(uuid)
	}(session.UUID)
	return session
}

func (s *Service) waitForAuthSession(ctx context.Context, session *PendingAuth) error {
	if session == nil {
		return fmt.Errorf("missing Outlook sign-in session")
	}
	start := time.Now()
	debugf("waitForAuthSession start session=%q status=%q deadline_in=%s", session.UUID, session.Status, debugDeadline(ctx))
	select {
	case <-ctx.Done():
		debugf("waitForAuthSession context_done session=%q err=%v elapsed=%s", session.UUID, ctx.Err(), time.Since(start).Round(time.Millisecond))
		return fmt.Errorf("Outlook sign-in was not completed: %w", ctx.Err())
	case <-session.Done():
	}
	current, ok := s.pending.Get(session.UUID)
	if !ok {
		debugf("waitForAuthSession missing session=%q elapsed=%s", session.UUID, time.Since(start).Round(time.Millisecond))
		return fmt.Errorf("Outlook sign-in session disappeared")
	}
	debugf("waitForAuthSession done session=%q status=%q error=%q elapsed=%s", session.UUID, current.Status, current.Error, time.Since(start).Round(time.Millisecond))
	switch current.Status {
	case AuthStatusAuthenticated:
		return nil
	case AuthStatusExpired:
		return fmt.Errorf("Outlook sign-in session expired")
	case AuthStatusCanceled:
		return fmt.Errorf("Outlook sign-in session was canceled")
	case AuthStatusFailed:
		if current.Error != "" {
			return fmt.Errorf("Outlook sign-in failed: %s", current.Error)
		}
		return fmt.Errorf("Outlook sign-in failed")
	default:
		return fmt.Errorf("Outlook sign-in was not completed")
	}
}

// sessionOrNamespace prefers transport session id else auth namespace
func (s *Service) sessionOrNamespace(ctx context.Context) string {
	if d, err := s.ns.Namespace(ctx); err == nil && d.Name != "" {
		return d.Name
	}
	return "default"
}

// ElicitCooldown returns cooldown between repeated elicitations; default 60s.
func (s *Service) ElicitCooldown() time.Duration {
	s.tunCoolOnce.Do(func() {
		if v := strings.TrimSpace(os.Getenv("OUTLOOK_MCP_ELICIT_COOLDOWN_SECS")); v != "" {
			if n, err := time.ParseDuration(v + "s"); err == nil {
				s.tunCooldown = n
			}
		}
		if s.tunCooldown == 0 {
			s.tunCooldown = 60 * time.Second
		}
	})
	return s.tunCooldown
}

// maybeElicitOnce emits at most once per cooldown window for session and global scopes.
func (s *Service) maybeElicitOnce(ctx context.Context, alias, tenantID, msg string, prompt func(string)) {
	if prompt == nil {
		return
	}
	sess := s.sessionOrNamespace(ctx)
	keySess := "elicit|" + safePart(sess) + "|" + safePart(alias) + "|" + safePart(tenantID)
	keyGlob := "elicit|" + safePart(alias) + "|" + safePart(tenantID)
	now := time.Now()
	cooldown := s.ElicitCooldown()
	s.elicitMu.Lock()
	if t, ok := s.elicited[keySess]; ok && now.Sub(t) < cooldown {
		s.elicitMu.Unlock()
		return
	}
	if t, ok := s.elicitedGlobal[keyGlob]; ok && now.Sub(t) < cooldown {
		s.elicitMu.Unlock()
		return
	}
	s.elicited[keySess] = now
	s.elicitedGlobal[keyGlob] = now
	s.elicitMu.Unlock()
	prompt(msg)
}

// clearElicitedAll clears dedupe entries for any session for alias/tenant.
func (s *Service) clearElicitedAll(alias, tenantID string) {
	s.elicitMu.Lock()
	for k := range s.elicited {
		parts := strings.Split(k, "|")
		if len(parts) >= 4 {
			if parts[2] == safePart(alias) && parts[3] == safePart(tenantID) {
				delete(s.elicited, k)
			}
		}
	}
	delete(s.elicitedGlobal, "elicit|"+safePart(alias)+"|"+safePart(tenantID))
	s.elicitMu.Unlock()
}

// local safePart for key building (avoid special characters)
func safePart(s string) string {
	s = strings.TrimSpace(s)
	repl := strings.NewReplacer("|", "_", " ", "_")
	return repl.Replace(s)
}
