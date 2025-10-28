package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"sync"
    "time"
    "unicode/utf8"

	"github.com/google/uuid"
	"github.com/viant/jsonrpc"
	protoclient "github.com/viant/mcp-protocol/client"
	oa "github.com/viant/mcp-toolbox/auth"
	"github.com/viant/mcp-toolbox/github/adapter"
)

type Service struct {
	baseURL    string
	useText    bool
	pending    *PendingAuths
	auth       *oa.Service
	clientID   string
	storageDir string

	mu             sync.RWMutex
	tokens         map[string]string // key(ns|alias|domain[|owner|repo[|oauth:clientID]]) -> access token
	runner         cmdRunner
	makeContentAPI func(domain string) contentAPI
	// no alias forcing/defaulting; rely on explicit alias or inference

	// treeCache stores full repo tree entries fetched via the Trees API
	// keyed by domain|owner|repo for recursive root listings.
	treeMu    sync.RWMutex
	treeCache map[string]treeCacheEntry

	// elicit guards to avoid spamming multiple prompts for the same ns/alias/domain
	elicitMu sync.Mutex
	elicited map[string]time.Time
	// global dedup across sessions per alias/domain
	elicitedGlobal map[string]time.Time

	// token waiters per alias/domain
	waitMu  sync.Mutex
	waiters map[string][]chan struct{}

    // cached tunables
    tunWaitOnce  sync.Once
    tunCoolOnce  sync.Once
    tunWait      time.Duration
    tunCooldown  time.Duration
}

// treeCacheEntry holds cached tree entries with expiration.
type treeCacheEntry struct {
	entries  []adapter.TreeEntry
	expireAt time.Time
}

func NewService(cfg *Config) *Service {
	if cfg == nil {
		cfg = &Config{}
	}
	useText := !cfg.UseData
	return &Service{
		baseURL:        cfg.CallbackBaseURL,
		useText:        useText,
		pending:        NewPendingAuths(),
		auth:           oa.New(),
		clientID:       cfg.ClientID,
		storageDir:     cfg.StorageDir,
		tokens:         map[string]string{},
		runner:         defaultCmdRunner{},
		makeContentAPI: func(domain string) contentAPI { return adapter.New(domain) },
		treeCache:      map[string]treeCacheEntry{},
		elicited:       map[string]time.Time{},
		elicitedGlobal: map[string]time.Time{},
		waiters:        map[string][]chan struct{}{},
	}
}

type contentAPI interface {
	ListContents(ctx context.Context, token, owner, name, path, ref string) ([]adapter.ContentItem, error)
	GetFileContent(ctx context.Context, token, owner, name, path, ref string) ([]byte, error)
}

func (s *Service) RegisterHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/github/auth/device/", s.DeviceHandler())
	mux.HandleFunc("/github/auth/pending", s.PendingListHandler())
	mux.HandleFunc("/github/auth/pending/clear", s.PendingClearHandler())
	mux.HandleFunc("/github/auth/token", s.TokenIngestHandler())
	mux.HandleFunc("/github/auth/start", s.DeviceStartHandler())
	mux.HandleFunc("/github/auth/check", s.TokenCheckHandler())
	mux.HandleFunc("/github/auth/oob", s.OOBHandler())
	mux.HandleFunc("/github/auth/verify", s.VerifyHandler())
}

func (s *Service) tokenKey(ns, alias, domain string) string {
	if domain == "" {
		domain = "github.com"
	}
	return joinKey(ns, alias, domain)
}
func (s *Service) tokenKeyOAuth(ns, alias, domain, clientID string) string {
	if domain == "" {
		domain = "github.com"
	}
	if clientID == "" {
		return s.tokenKey(ns, alias, domain)
	}
	return joinKey(ns, alias, domain, "oauth:"+clientID)
}
func (s *Service) tokenKeyRepo(ns, alias, domain, owner, name string) string {
	if domain == "" {
		domain = "github.com"
	}
	return joinKey(ns, alias, domain, owner, name)
}
func (s *Service) tokenKeyRepoOAuth(ns, alias, domain, owner, name, clientID string) string {
	if clientID == "" {
		return s.tokenKeyRepo(ns, alias, domain, owner, name)
	}
	return joinKey(ns, alias, domain, owner, name, "oauth:"+clientID)
}

// repoKey builds a cache key for a repository scoped to domain/owner/name.
func (s *Service) repoKey(domain, owner, name string) string {
	if domain == "" {
		domain = "github.com"
	}
	return domain + "|" + owner + "|" + name
}
func (s *Service) loadToken(ns, alias, domain string) string {
	key := s.tokenKey(ns, alias, domain)
	s.mu.RLock()
	t := s.tokens[key]
	s.mu.RUnlock()
	return t
}

// loadTokenPreferred resolves token by preferring repo-level (oauth then plain), then domain-level (oauth then plain).
func (s *Service) loadTokenPreferred(ns, alias, domain, owner, name string) string {
	s.mu.RLock()
	var out string
	// repo-level with oauth key
	if owner != "" && name != "" && s.clientID != "" {
		if t := s.tokens[s.tokenKeyRepoOAuth(ns, alias, domain, owner, name, s.clientID)]; t != "" {
			out = t
		}
	}
	// repo-level plain
	if out == "" && owner != "" && name != "" {
		if t := s.tokens[s.tokenKeyRepo(ns, alias, domain, owner, name)]; t != "" {
			out = t
		}
	}
	// domain-level with oauth key
	if out == "" && s.clientID != "" {
		if t := s.tokens[s.tokenKeyOAuth(ns, alias, domain, s.clientID)]; t != "" {
			out = t
		}
	}
	// domain-level plain
	if out == "" {
		if t := s.tokens[s.tokenKey(ns, alias, domain)]; t != "" {
			out = t
		}
	}
	s.mu.RUnlock()
	return out
}
func (s *Service) saveToken(ns, alias, domain, token string) {
	key := s.tokenKey(ns, alias, domain)
	s.mu.Lock()
	s.tokens[key] = token
	s.mu.Unlock()
}
func (s *Service) saveTokenRepo(ns, alias, domain, owner, name, token string, oauthKey bool) {
	s.mu.Lock()
	if oauthKey && s.clientID != "" {
		s.tokens[s.tokenKeyRepoOAuth(ns, alias, domain, owner, name, s.clientID)] = token
	} else {
		s.tokens[s.tokenKeyRepo(ns, alias, domain, owner, name)] = token
	}
	s.mu.Unlock()
}
func (s *Service) saveTokenDomain(ns, alias, domain, token string, oauthKey bool) {
	s.mu.Lock()
	if oauthKey && s.clientID != "" {
		s.tokens[s.tokenKeyOAuth(ns, alias, domain, s.clientID)] = token
	} else {
		s.tokens[s.tokenKey(ns, alias, domain)] = token
	}
	s.mu.Unlock()
}
func (s *Service) clearToken(ns, alias, domain string) {
	key := s.tokenKey(ns, alias, domain)
	s.mu.Lock()
	delete(s.tokens, key)
	s.mu.Unlock()
}

// loadTokenPreferredAnyNS scans tokens across all namespaces to find a usable token.
// Preference mirrors loadTokenPreferred: repo-level (oauth then plain), then domain-level (oauth then plain).
func (s *Service) loadTokenPreferredAnyNS(alias, domain, owner, name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	safeAlias := safePart(alias)
	safeDomain := safePart(domain)
	// repo-level
	for k, _ := range s.tokens {
		parts := strings.Split(k, "|")
		// expect ns|alias|domain|owner|repo[|oauth:client]
		if len(parts) >= 5 && parts[1] == safeAlias && parts[2] == safeDomain {
			if owner != "" && name != "" && parts[3] == safePart(owner) && parts[4] == safePart(name) {
				// prefer oauth key if present by scanning twice; handled below
			}
		}
	}
	// first pass: repo-level oauth
	if s.clientID != "" && owner != "" && name != "" {
		for k, v := range s.tokens {
			parts := strings.Split(k, "|")
			if len(parts) == 6 && parts[1] == safeAlias && parts[2] == safeDomain && parts[3] == safePart(owner) && parts[4] == safePart(name) && strings.HasPrefix(parts[5], "oauth:") {
				if v != "" {
					return v
				}
			}
		}
	}
	// repo-level plain
	if owner != "" && name != "" {
		for k, v := range s.tokens {
			parts := strings.Split(k, "|")
			if len(parts) == 5 && parts[1] == safeAlias && parts[2] == safeDomain && parts[3] == safePart(owner) && parts[4] == safePart(name) {
				if v != "" {
					return v
				}
			}
		}
	}
	// domain-level oauth
	if s.clientID != "" {
		for k, v := range s.tokens {
			parts := strings.Split(k, "|")
			if len(parts) == 4 && parts[1] == safeAlias && parts[2] == safeDomain && strings.HasPrefix(parts[3], "oauth:") {
				if v != "" {
					return v
				}
			}
		}
	}
	// domain-level plain
	for k, v := range s.tokens {
		parts := strings.Split(k, "|")
		if len(parts) == 3 && parts[1] == safeAlias && parts[2] == safeDomain {
			if v != "" {
				return v
			}
		}
	}
	return ""
}

func (s *Service) Credential(ctx context.Context, alias, domain string, prompt func(string)) (string, error) {
	alias = s.normalizeAlias(alias)
	ns, _ := s.auth.Namespace(ctx)
	if ns == "" {
		ns = "default"
	}
	if t := s.loadToken(ns, alias, domain); t != "" {
		return t, nil
	}
	return s.startDeviceFlow(ctx, alias, domain, prompt)
}

// inferAlias tries to pick an alias automatically when caller omitted it.
// Preference order:
// 1) If exactly one repo-scoped token exists for ns/domain/owner/name, use its alias.
// 2) Else if exactly one domain-scoped token exists for ns/domain, use its alias.
// Returns the inferred alias (or "") and the set of candidate aliases found.
func (s *Service) inferAlias(ctx context.Context, domain, owner, name string) (string, []string) {
	ns, _ := s.auth.Namespace(ctx)
	if ns == "" {
		ns = "default"
	}
	if domain == "" {
		domain = "github.com"
	}
	repoAliases := map[string]struct{}{}
	domAliases := map[string]struct{}{}
	s.mu.RLock()
	for k := range s.tokens {
		parts := strings.Split(k, "|")
		// Expect at least ns|alias|domain
		if len(parts) < 3 {
			continue
		}
		if parts[0] != safePart(ns) {
			continue
		}
		if parts[2] != safePart(domain) {
			continue
		}
		alias := parts[1]
		if len(parts) >= 5 && owner != "" && name != "" {
			if parts[3] == safePart(owner) && parts[4] == safePart(name) {
				repoAliases[alias] = struct{}{}
				continue
			}
		}
		// domain level token
		domAliases[alias] = struct{}{}
	}
	s.mu.RUnlock()
	uniq := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for a := range m {
			out = append(out, a)
		}
		return out
	}
	repoList := uniq(repoAliases)
	if len(repoList) == 1 {
		return repoList[0], repoList
	}
	// merge unique
	allSet := map[string]struct{}{}
	for a := range repoAliases {
		allSet[a] = struct{}{}
	}
	for a := range domAliases {
		allSet[a] = struct{}{}
	}
	all := uniq(allSet)
	if len(all) == 1 {
		return all[0], all
	}
	return "", all
}

func (s *Service) startDeviceFlow(ctx context.Context, alias, domain string, prompt func(string)) (string, error) {
	type dcResp struct {
		DeviceCode, UserCode, VerificationURI string
		ExpiresIn, Interval                   int
	}
	form := fmt.Sprintf("client_id=%s&scope=repo%%20read:user", s.clientID)
	host := domain
	if host == "" {
		host = "github.com"
	}
	deviceURL := fmt.Sprintf("https://%s/login/device/code", host)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, deviceURL, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("device code failed: %s", resp.Status)
	}
	var dcr dcResp
	if err := json.NewDecoder(resp.Body).Decode(&dcr); err != nil {
		return "", err
	}
	ns, _ := s.auth.Namespace(ctx)
	id := uuid.New().String()
	s.pending.Put(&PendingAuth{UUID: id, Alias: alias, Namespace: ns, UserCode: dcr.UserCode, VerifyURL: dcr.VerificationURI})
	// Prefer unified OOB page which can accept token/basic or show device code.
	q := neturl.Values{}
	q.Set("alias", alias)
	if domain != "" {
		q.Set("domain", domain)
	}
	q.Set("uuid", id)
	oob := strings.TrimRight(s.baseURL, "/") + "/github/auth/oob?" + q.Encode()
	if prompt != nil {
		prompt(fmt.Sprintf("Open %s and follow instructions (code: %s)", oob, dcr.UserCode))
	}
	type tokResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	for {
		form := fmt.Sprintf("client_id=%s&device_code=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code", s.clientID, dcr.DeviceCode)
		tokenURL := fmt.Sprintf("https://%s/login/oauth/access_token", host)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		var tr tokResp
		_ = json.NewDecoder(resp.Body).Decode(&tr)
		resp.Body.Close()
		if tr.AccessToken != "" {
			ns2, _ := s.auth.Namespace(ctx)
			if ns2 == "" {
				ns2 = ns
			}
			s.saveToken(ns2, alias, domain, tr.AccessToken)
			s.clearElicitedAll(alias, domain)
			s.notifyToken(alias, domain)
			return tr.AccessToken, nil
		}
		if tr.Error == "authorization_pending" || tr.Error == "slow_down" {
			if dcr.Interval <= 0 {
				dcr.Interval = 5
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-timeAfterSeconds(dcr.Interval):
			}
			continue
		}
		if tr.Error != "" {
			return "", fmt.Errorf("device flow error: %s", tr.Error)
		}
	}
}

func timeAfterSeconds(n int) <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() { time.Sleep(time.Duration(n) * time.Second); ch <- struct{}{} }()
	return ch
}

func (s *Service) DeviceHandler() http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 4 {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		uuid := parts[3]
		pend, ok := s.pending.Get(uuid)
		if !ok {
			http.Error(w, "no pending auth", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, buildDeviceLoginHTML(pend.VerifyURL, pend.UserCode))
	}
}
func buildDeviceLoginHTML(url, code string) string {
	escURL := html.EscapeString(url)
	escCode := html.EscapeString(code)
	return fmt.Sprintf(`<html><body style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;"><h3>Sign in to GitHub</h3><p>Click to open: <a href="%[1]s" target="_blank" rel="noopener noreferrer">%[1]s</a></p><p>Then enter this code:</p><p style="font-size:1.4em;font-weight:600;"><code>%[2]s</code> <button onclick="navigator.clipboard.writeText('%[2]s')">Copy</button></p><p>Keep this tab open; return to your assistant after completing sign-in.</p></body></html>`, escURL, escCode)
}
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
		type row struct{ UUID, Alias, Namespace, UserCode, VerifyURL string }
		out := make([]row, 0, len(list))
		for _, v := range list {
			out = append(out, row{UUID: v.UUID, Alias: v.Alias, Namespace: v.Namespace, UserCode: v.UserCode, VerifyURL: v.VerifyURL})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}
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

// TokenIngestHandler accepts a token via Authorization header (Bearer or Basic) or JSON body and stores it for alias/domain.
func (s *Service) TokenIngestHandler() http.HandlerFunc {
	type reqBody struct {
		Alias       string `json:"alias"`
		Domain      string `json:"domain"`
		Owner       string `json:"owner"`
		Repo        string `json:"repo"`
		AccessToken string `json:"access_token"`
		OAuthKey    bool   `json:"oauthKey"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		alias := r.URL.Query().Get("alias")
		domain := r.URL.Query().Get("domain")
		owner := r.URL.Query().Get("owner")
		repo := r.URL.Query().Get("repo")
		oauthKey := r.URL.Query().Get("oauthKey") == "true"
		var rb reqBody
		if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
			_ = json.NewDecoder(r.Body).Decode(&rb)
		}
		if alias == "" {
			alias = rb.Alias
		}
		alias = s.normalizeAlias(alias)
		if domain == "" {
			domain = rb.Domain
		}
		if owner == "" {
			owner = rb.Owner
		}
		if repo == "" {
			repo = rb.Repo
		}
		if !oauthKey {
			oauthKey = rb.OAuthKey
		}
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
			log.Printf("[github] token ingest: missing alias; domain=%s", domain)
			return
		}
		// Prefer JSON body token if provided; fall back to Authorization header
		token := strings.TrimSpace(rb.AccessToken)
		if token == "" {
			if auth := r.Header.Get("Authorization"); auth != "" {
				parts := strings.SplitN(auth, " ", 2)
				if len(parts) == 2 && strings.EqualFold(parts[0], "Basic") {
					if dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1])); err == nil {
						token = string(dec) // username:password
					}
				} else if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
					token = strings.TrimSpace(parts[1])
				}
				if token != "" {
					log.Printf("[github] token ingest: Authorization header parsed; alias=%s domain=%s", alias, domain)
				} else {
					log.Printf("[github] token ingest: Authorization header present but unparsable; alias=%s domain=%s", alias, domain)
				}
			}
		}
		if token == "" {
			http.Error(w, "access token missing", http.StatusBadRequest)
			log.Printf("[github] token ingest: missing token; alias=%s domain=%s", alias, domain)
			return
		}
		// Validate credentials against GitHub before saving to avoid storing invalid tokens.
		if domain == "" {
			domain = "github.com"
		}
		cli := adapter.New(domain)
		if err := cli.ValidateToken(r.Context(), token); err != nil {
			if errors.Is(err, adapter.ErrUnauthorized) {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
				return
			}
			http.Error(w, "credential validation failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		ns, _ := s.auth.Namespace(r.Context())
		if ns == "" {
			ns = "default"
		}
		if owner != "" && repo != "" {
			s.saveTokenRepo(ns, alias, domain, owner, repo, token, oauthKey)
			log.Printf("[github] token ingest: saved repo token; alias=%s domain=%s owner=%s repo=%s oauth=%v", alias, domain, owner, repo, oauthKey)
		} else {
			s.saveTokenDomain(ns, alias, domain, token, oauthKey)
			log.Printf("[github] token ingest: saved domain token; alias=%s domain=%s oauth=%v", alias, domain, oauthKey)
		}
		s.clearElicitedAll(alias, domain)
		s.notifyToken(alias, domain)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}
}

// DeviceStartHandler initiates device authorization and returns URL+code without blocking for completion.
func (s *Service) DeviceStartHandler() http.HandlerFunc {
	type reqBody struct {
		Alias  string `json:"alias"`
		Domain string `json:"domain"`
	}
	type dcResp struct {
		DeviceCode, UserCode, VerificationURI string
		ExpiresIn, Interval                   int
	}
	type respBody struct {
		UUID, OOBUrl, VerifyURL, UserCode string
		ExpiresIn, Interval               int
	}
	type tokResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if s.clientID == "" {
			http.Error(w, "service missing clientID", http.StatusBadRequest)
			return
		}
		alias := r.URL.Query().Get("alias")
		domain := r.URL.Query().Get("domain")
		var rb reqBody
		if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
			_ = json.NewDecoder(r.Body).Decode(&rb)
		}
		if alias == "" {
			alias = rb.Alias
		}
		if domain == "" {
			domain = rb.Domain
		}
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
			return
		}
		host := domain
		if host == "" {
			host = "github.com"
		}
		form := fmt.Sprintf("client_id=%s&scope=repo%%20read:user", s.clientID)
		deviceURL := fmt.Sprintf("https://%s/login/device/code", host)
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, deviceURL, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			http.Error(w, "device code failed: "+resp.Status, http.StatusBadGateway)
			return
		}
		var dcr dcResp
		if err := json.NewDecoder(resp.Body).Decode(&dcr); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		ns, _ := s.auth.Namespace(r.Context())
		id := uuid.New().String()
		s.pending.Put(&PendingAuth{UUID: id, Alias: alias, Namespace: ns, UserCode: dcr.UserCode, VerifyURL: dcr.VerificationURI})
		oob := strings.TrimRight(s.baseURL, "/") + "/github/auth/device/" + id
		// respond immediately with OOB url and code
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respBody{UUID: id, OOBUrl: oob, VerifyURL: dcr.VerificationURI, UserCode: dcr.UserCode, ExpiresIn: dcr.ExpiresIn, Interval: dcr.Interval})

		// Start background polling to exchange device_code for access token
		go func(ctx context.Context, alias, domain, deviceCode string, interval int) {
			if interval <= 0 {
				interval = 5
			}
			host := domain
			if host == "" {
				host = "github.com"
			}
			for {
				form := fmt.Sprintf("client_id=%s&device_code=%s&grant_type=urn:ietf:params:oauth:grant-type:device_code", s.clientID, deviceCode)
				tokenURL := fmt.Sprintf("https://%s/login/oauth/access_token", host)
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form))
				req.Header.Set("Accept", "application/json")
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return
				}
				var tr tokResp
				_ = json.NewDecoder(resp.Body).Decode(&tr)
				resp.Body.Close()
				if tr.AccessToken != "" {
					ns2, _ := s.auth.Namespace(ctx)
					if ns2 == "" {
						ns2 = ns
					}
					s.saveToken(ns2, alias, domain, tr.AccessToken)
					s.clearElicitedAll(alias, domain)
					s.notifyToken(alias, domain)
					return
				}
				if tr.Error == "authorization_pending" || tr.Error == "slow_down" {
					select {
					case <-ctx.Done():
						return
					case <-timeAfterSeconds(interval):
					}
					continue
				}
				return
			}
		}(r.Context(), alias, domain, dcr.DeviceCode, dcr.Interval)
	}
}

// TokenCheckHandler returns whether a token exists for alias/domain.
func (s *Service) TokenCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		alias := r.URL.Query().Get("alias")
		domain := r.URL.Query().Get("domain")
		owner := r.URL.Query().Get("owner")
		repo := r.URL.Query().Get("repo")
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
			return
		}
		alias = s.normalizeAlias(alias)
		ns, _ := s.auth.Namespace(r.Context())
		if ns == "" {
			ns = "default"
		}
		has := s.loadTokenPreferred(ns, alias, domain, owner, repo) != ""
		log.Printf("[github] token check: alias=%s domain=%s owner=%s repo=%s has=%v", alias, domain, owner, repo, has)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"hasToken": has})
	}
}

// VerifyHandler checks whether the provided/stored credential can access the repo's default branch tree.
// GET /github/auth/verify?alias=...&domain=...&url=domain/owner/repo
func (s *Service) VerifyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		alias := s.normalizeAlias(r.URL.Query().Get("alias"))
		domain := r.URL.Query().Get("domain")
		u := strings.TrimSpace(r.URL.Query().Get("url"))
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
			return
		}
		if u == "" {
			http.Error(w, "url required (domain/owner/repo)", http.StatusBadRequest)
			return
		}
		// parse domain/owner/name
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			if p := strings.Index(u, "://"); p > 0 {
				u = u[p+3:]
			}
		}
		parts := strings.Split(strings.Trim(u, "/"), "/")
		if len(parts) < 3 {
			http.Error(w, "invalid url; expected domain/owner/repo", http.StatusBadRequest)
			return
		}
		if domain == "" {
			domain = parts[0]
		} // prefer explicit query param if provided
		owner, name := parts[1], parts[2]
		ns, _ := s.auth.Namespace(r.Context())
		if ns == "" {
			ns = "default"
		}
		token := s.loadToken(ns, alias, domain)
		if token == "" {
			http.Error(w, "no token for alias/domain", http.StatusUnauthorized)
			return
		}
		cli := adapter.New(domain)
		// Resolve default branch
		def, err := cli.GetRepoDefaultBranch(r.Context(), token, owner, name)
		if err != nil {
			http.Error(w, "verify: default branch: "+err.Error(), http.StatusUnauthorized)
			return
		}
        // Resolve commit tree; tolerate 422 by attempting heads/ prefix and finally skipping
        if _, err := cli.GetCommitTreeSHA(r.Context(), token, owner, name, def); err != nil {
            // try heads/def and refs/heads/def implicitly handled inside GetCommitTreeSHA; if still errors, proceed
            if serviceDebug() {
                log.Printf("[github] verify: commit/tree check failed for %s/%s@%s: %v; tolerating", owner, name, def, err)
            }
        }
        w.Header().Set("Content-Type", "application/json")
        _ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "defaultBranch": def})
    }
}

// OOBHandler serves a page to collect credentials: bearer token, basic creds, or start device flow.
func (s *Service) OOBHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		alias := r.URL.Query().Get("alias")
		domain := r.URL.Query().Get("domain")
		uuid := r.URL.Query().Get("uuid")
		if alias == "" {
			alias = "default"
		}
		host := domain
		if host == "" {
			host = "github.com"
		}
		base := strings.TrimRight(s.baseURL, "/")
		// If uuid is provided and pending exists, show device code info initially.
		deviceInitial := ""
		if uuid != "" {
			if pend, ok := s.pending.Get(uuid); ok && pend != nil {
				deviceInitial = fmt.Sprintf("Open <a href=\"%s\" target=\"_blank\" rel=\"noopener\">%s</a> and enter code <code>%s</code>.", html.EscapeString(pend.VerifyURL), html.EscapeString(pend.VerifyURL), html.EscapeString(pend.UserCode))
			}
		}
		// Simple HTML + inline JS for user interaction.
		repourl := r.URL.Query().Get("url")
		htmlTmpl := `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GitHub Authorization</title>
  <style>
    :root { --bg:#f3f4f6; --card:#ffffff; --muted:#6b7280; --fg:#111827; --primary:#dc4b43; --primary-600:#c0392b; --ring:#e5e7eb; }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{margin:0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--fg); display:flex; align-items:center; justify-content:center; padding:24px}
    .card{width:100%; max-width:640px; background:var(--card); border-radius:14px; box-shadow:0 10px 30px rgba(0,0,0,.08); overflow:hidden; border:1px solid var(--ring)}
    .header{padding:28px 28px 0}
    .brand{display:flex; align-items:center; gap:10px; color:var(--primary); font-weight:800; letter-spacing:.08em}
    .brand svg{height:22px}
    .title{margin:12px 0 6px; font-size:22px; font-weight:700}
    .subtitle{margin:0; color:var(--muted); font-size:14px}
    .body{padding:24px 28px 28px}
    .stack{display:flex; flex-direction:column; gap:12px; margin-bottom:16px}
    label{display:block; font-weight:600; margin-bottom:6px}
    input{width:100%; padding:12px 14px; border:1px solid var(--ring); border-radius:10px; font-size:15px; outline:none}
    input:focus{border-color:var(--primary); box-shadow:0 0 0 3px rgba(220,75,67,.15)}
    .hint{font-size:12px; color:var(--muted); margin-top:4px}
    #status.error{color:#b91c1c}
    input.error{border-color:#dc2626 !important; box-shadow:0 0 0 3px rgba(220,38,38,.15) !important}
    .tabs{display:flex; gap:8px; margin:10px 0 18px}
    .tab{flex:0 0 auto; padding:8px 12px; border:1px solid var(--ring); border-radius:999px; cursor:pointer; font-size:13px; color:#374151; background:#fafafa}
    .tab.active{background:var(--primary); color:#fff; border-color:var(--primary)}
    .section{display:none}
    .section.active{display:block}
    .actions{display:flex; gap:10px; margin-top:18px}
    .btn{appearance:none; border:none; cursor:pointer; border-radius:10px; padding:10px 14px; font-size:15px}
    .btn.primary{background:var(--primary); color:#fff}
    .btn.primary:hover{background:var(--primary-600)}
    .btn.ghost{background:#f9fafb; border:1px solid var(--ring)}
    code{background:#f6f7f9; padding:2px 6px; border-radius:6px}
    .footer{padding:14px 28px 24px; color:var(--muted); font-size:12px}
    .device{margin-top:8px; padding:10px; background:#fff8f8; border:1px dashed var(--primary); border-radius:10px}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="brand">
        <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 .2a8 8 0 0 0-2.53 15.6c.4.07.55-.17.55-.38v-1.32c-2.26.49-2.73-1.09-2.73-1.09-.36-.92-.89-1.16-.89-1.16-.73-.5.06-.49.06-.49.81.06 1.24.83 1.24.83.72 1.23 1.88.88 2.34.67.07-.52.28-.88.5-1.08-1.8-.2-3.69-.9-3.69-4.02 0-.89.32-1.62.84-2.19-.08-.2-.36-1.01.08-2.1 0 0 .68-.22 2.22.84a7.6 7.6 0 0 1 4.05 0c1.54-1.06 2.22-.84 2.22-.84.44 1.09.16 1.9.08 2.1.52.57.84 1.3.84 2.19 0 3.13-1.89 3.82-3.7 4.02.29.25.54.74.54 1.5v2.23c0 .21.14.45.55.38A8 8 0 0 0 8 .2Z"/></svg>
        <span>GitHub</span>
      </div>
      <h1 class="title">Authorize GitHub Access</h1>
      <p class="subtitle">Alias and host are prefilled; choose a sign‑in method below.</p>
    </div>
    <div class="body">
      <div class="stack">
        <div>
          <label for="alias">Alias</label>
          <input id="alias" value="{{ALIAS}}" />
        </div>
        <div>
          <label for="domain">Domain</label>
          <input id="domain" value="{{DOMAIN}}" />
        </div>
      </div>

      <div class="tabs">
        <button class="tab" data-tab="token">Token</button>
        <button class="tab active" data-tab="basic">Username/Password</button>
        <button class="tab" data-tab="device">Device Flow</button>
      </div>

      <div id="sec-token" class="section">
        <label for="bearer">Personal Access Token</label>
        <input id="bearer" placeholder="ghp_..." />
        <div class="hint">Paste a GitHub token with the required scopes.</div>
      </div>

      <div id="sec-basic" class="section active">
        <label for="user">Username</label>
        <input id="user" placeholder="Username" />
        <label for="pass" style="margin-top:10px">Password or Token</label>
        <input id="pass" type="password" placeholder="••••••••" />
        <div class="hint">For GitHub.com, basic auth requires a token as password.</div>
      </div>

      <div id="sec-device" class="section">
        <div class="device" id="deviceInfo">{{DEVICE}}</div>
        <div class="hint">Start device flow to sign in on github.com and return here.</div>
      </div>

      <label for="repourl" style="margin-top:16px">Repository (optional)</label>
      <input id="repourl" value="{{REPOURL}}" placeholder="github.vianttech.com/owner/repo" />

      <div class="actions">
        <button class="btn primary" onclick="onOK()">Continue</button>
        <button class="btn ghost" onclick="onCancel()">Cancel</button>
        <button class="btn ghost" onclick="onReject()">Reject</button>
      </div>

      <div id="status" class="hint" style="margin-top:10px"></div>
    </div>
    <div class="footer">You can switch method tabs at any time. We never store your password; tokens are kept locally for this session.</div>
  </div>

<script>
document.querySelectorAll('.tab').forEach(el => el.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  const tab = el.getAttribute('data-tab');
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.getElementById('sec-' + tab).classList.add('active');
  // clear previous error highlights when switching methods
  document.getElementById('status').classList.remove('error');
  ['bearer','user','pass'].forEach(id=>{ const n=document.getElementById(id); if(n) n.classList.remove('error')});
}));
async function pollCheck(alias, domain) {
  const url = '{{BASE}}/github/auth/check?alias=' + encodeURIComponent(alias) + '&domain=' + encodeURIComponent(domain||'');
  for (let i=0; i<60; i++) { // ~60 * 2s = 2 minutes
    const r = await fetch(url);
    const j = await r.json();
    if (j.hasToken) return true;
    await new Promise(rs => setTimeout(rs, 2000));
  }
  return false;
}
async function startDevice() {
  const alias = document.getElementById('alias').value.trim();
  const domain = document.getElementById('domain').value.trim();
  const el = document.getElementById('deviceInfo'); el.textContent = 'Starting device flow...';
  const r = await fetch('{{BASE}}/github/auth/start?alias=' + encodeURIComponent(alias) + '&domain=' + encodeURIComponent(domain||''), { method:'POST' });
  if (!r.ok) { el.textContent = 'Start error: ' + r.status; return }
  const j = await r.json();
  el.innerHTML = 'Open <a href="' + j.VerifyURL + '" target="_blank" rel="noopener">' + j.VerifyURL + '</a> and enter code <code>' + j.UserCode + '</code>.\nThen return here.';
  if (await pollCheck(alias, domain)) { el.innerHTML += '<div>Token saved.</div>'; tryClose('Device flow completed.'); }
}
async function onOK() {
  const alias = document.getElementById('alias').value.trim();
  const domain = document.getElementById('domain').value.trim();
  const bearer = document.getElementById('bearer').value.trim();
  const user = document.getElementById('user').value.trim();
  const pass = document.getElementById('pass').value.trim();
  const status = document.getElementById('status'); status.textContent = 'Processing...'; status.classList.remove('error');
  const flagTokenError = (msg)=>{ status.textContent = msg; status.classList.add('error'); const b=document.getElementById('bearer'); if(b) b.classList.add('error'); };
  const flagBasicError = (msg)=>{ status.textContent = msg; status.classList.add('error'); ['user','pass'].forEach(id=>{ const n=document.getElementById(id); if(n) n.classList.add('error')}); };
  try {
    if (bearer) {
      const r = await fetch('{{BASE}}/github/auth/token?alias=' + encodeURIComponent(alias) + '&domain=' + encodeURIComponent(domain||''), { method:'POST', headers: { 'Authorization': 'Bearer ' + bearer } });
      if (!r.ok) { const txt = await r.text(); flagTokenError(r.status===401 ? 'Invalid token' : ('Save failed: ' + txt)); return }
      if (await pollCheck(alias, domain)) {
        const repourl = document.getElementById('repourl').value.trim();
        if (repourl) {
          const vr = await fetch('{{BASE}}/github/auth/verify?alias=' + encodeURIComponent(alias) + '&domain=' + encodeURIComponent(domain||'') + '&url=' + encodeURIComponent(repourl));
          if (!vr.ok) { flagTokenError('Verify failed: ' + (await vr.text())); return; }
        }
        status.textContent = 'OK: token saved'; tryClose('OK');
      } else { status.textContent = 'Saved, but token not visible in check'; tryClose('Saved'); }
      return;
    }
    if (user || pass) {
      const basic = btoa((user||'') + ':' + (pass||''));
      const r = await fetch('{{BASE}}/github/auth/token?alias=' + encodeURIComponent(alias) + '&domain=' + encodeURIComponent(domain||''), { method:'POST', headers: { 'Authorization': 'Basic ' + basic } });
      if (!r.ok) { const txt = await r.text(); flagBasicError(r.status===401 ? 'Invalid username or token' : ('Save failed: ' + txt)); return }
      if (await pollCheck(alias, domain)) {
        const repourl = document.getElementById('repourl').value.trim();
        if (repourl) {
          const vr = await fetch('{{BASE}}/github/auth/verify?alias=' + encodeURIComponent(alias) + '&domain=' + encodeURIComponent(domain||'') + '&url=' + encodeURIComponent(repourl));
          if (!vr.ok) { flagBasicError('Verify failed: ' + (await vr.text())); return; }
        }
        status.textContent = 'OK: basic saved'; tryClose('OK');
      } else { status.textContent = 'Saved, but not visible in check'; tryClose('Saved'); }
      return;
    }
    await startDevice(); status.textContent = 'Device flow started.';
  } catch (e) { status.textContent = e.message; }
}
function tryClose(msg){
  try { window.close(); } catch(e){}
  // If window doesn't close (opened as a tab), show a message
  const s = document.getElementById('status');
  if (s) s.textContent = msg + ' — you can close this tab now.';
}
function onCancel(){ document.getElementById('status').textContent = 'Canceled by user.'; tryClose('Canceled'); }
function onReject(){ document.getElementById('status').textContent = 'Rejected by user.'; tryClose('Rejected'); }
 </script>
</body></html>`
		// Replace placeholders without % formatting issues.
		repl := strings.NewReplacer(
			"{{ALIAS}}", html.EscapeString(alias),
			"{{DOMAIN}}", html.EscapeString(host),
			"{{BASE}}", html.EscapeString(base),
			"{{DEVICE}}", deviceInitial,
			"{{REPOURL}}", html.EscapeString(repourl),
		)
		htmlPage := repl.Replace(htmlTmpl)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, htmlPage)
	}
}

func parseAuthHeaderToken(header string) string {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	scheme, val := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
	switch scheme {
	case "bearer":
		return val
	case "basic":
		dec, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return ""
		}
		creds := string(dec)
		if i := strings.IndexByte(creds, ':'); i != -1 {
			return creds[i+1:]
		}
		return creds
	}
	return ""
}

func (s *Service) UseTextField() bool                         { return s.useText }
func (s *Service) BaseURL() string                            { return s.baseURL }
func (s *Service) StorageDir() string                         { return s.storageDir }
func (s *Service) ClientID() string                           { return s.clientID }
func (s *Service) NewOperationsHook(_ protoclient.Operations) {}

func (s *Service) sessionOrNamespace(ctx context.Context) string {
	// Prefer transport session id set by JSON-RPC transport
	if v := ctx.Value(jsonrpc.SessionKey); v != nil {
		if id, ok := v.(string); ok && id != "" {
			return id
		}
	}
	// Fallback to auth namespace as a coarse session scope
	if v, err := s.auth.Namespace(ctx); err == nil && v != "" {
		return v
	}
	return "default"
}

// WaitTimeout returns maximum time to wait for credentials; configurable via GITHUB_MCP_WAIT_SECS (default 300s).
func (s *Service) WaitTimeout() time.Duration {
    s.tunWaitOnce.Do(func() {
        if v := strings.TrimSpace(os.Getenv("GITHUB_MCP_WAIT_SECS")); v != "" {
            if n, err := time.ParseDuration(v + "s"); err == nil {
                s.tunWait = n
            }
        }
        if s.tunWait == 0 {
            s.tunWait = 300 * time.Second
        }
    })
    return s.tunWait
}

// ElicitCooldown returns cooldown between repeated elicitations; configurable via GITHUB_MCP_ELICIT_COOLDOWN_SECS (default 60s).
func (s *Service) ElicitCooldown() time.Duration {
    s.tunCoolOnce.Do(func() {
        if v := strings.TrimSpace(os.Getenv("GITHUB_MCP_ELICIT_COOLDOWN_SECS")); v != "" {
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

func (s *Service) tokenWaitKey(alias, domain string) string { return joinKey("wait", alias, domain) }

// notifyToken wakes any goroutines waiting for a token for (alias,domain).
func (s *Service) notifyToken(alias, domain string) {
	key := s.tokenWaitKey(alias, domain)
	s.waitMu.Lock()
	lst := s.waiters[key]
	delete(s.waiters, key)
	s.waitMu.Unlock()
	if serviceDebug() {
		log.Printf("[github] notifyToken alias=%s domain=%s waiters=%d", alias, domain, len(lst))
	}
	for _, ch := range lst {
		close(ch)
	}
}

func serviceDebug() bool {
    // Enable debug logs only when GITHUB_MCP_DEBUG is truthy
    // (any non-empty value other than 0/false)
    v := strings.ToLower(strings.TrimSpace(os.Getenv("GITHUB_MCP_DEBUG")))
    return v != "" && v != "0" && v != "false"
}

// maybeElicitOnce emits a single OOB prompt per (ns,alias,domain) within a cooldown window.
func (s *Service) maybeElicitOnce(ctx context.Context, alias, domain, owner, name string, prompt func(string)) {
	if prompt == nil {
		return
	}
	sess := s.sessionOrNamespace(ctx)
	keySess := joinKey("elicit", sess, alias, domain)
	keyGlob := joinKey("elicit", alias, domain)
	now := time.Now()
	cooldown := s.ElicitCooldown()
	s.elicitMu.Lock()
	if t, ok := s.elicited[keySess]; ok && now.Sub(t) < cooldown {
		if serviceDebug() {
			log.Printf("[github] elicit skip: session cooldown sess=%s alias=%s domain=%s", sess, alias, domain)
		}
		s.elicitMu.Unlock()
		return
	}
	if t, ok := s.elicitedGlobal[keyGlob]; ok && now.Sub(t) < cooldown {
		if serviceDebug() {
			log.Printf("[github] elicit skip: global cooldown alias=%s domain=%s", alias, domain)
		}
		s.elicitMu.Unlock()
		return
	}
	s.elicited[keySess] = now
	s.elicitedGlobal[keyGlob] = now
	s.elicitMu.Unlock()
	if serviceDebug() {
		log.Printf("[github] elicit emit: sess=%s alias=%s domain=%s owner=%s repo=%s", sess, alias, domain, owner, name)
	}
	base := s.BaseURL()
	q := neturl.Values{}
	q.Set("alias", alias)
	if domain != "" {
		q.Set("domain", domain)
	}
	// Include repo url hint when available
	if owner != "" && name != "" {
		q.Set("url", fmt.Sprintf("%s/%s/%s", domain, owner, name))
	}
	prompt(fmt.Sprintf("Open %s/github/auth/oob?%s to provide credentials", strings.TrimRight(base, "/"), q.Encode()))
}

// clearElicitedAll clears dedupe entries for any session for this alias/domain.
func (s *Service) clearElicitedAll(alias, domain string) {
	s.elicitMu.Lock()
	for k := range s.elicited {
		parts := strings.Split(k, "|")
		// key format: elicit|session|alias|domain
		if len(parts) >= 4 {
			if parts[2] == safePart(alias) && parts[3] == safePart(domain) {
				delete(s.elicited, k)
			}
		}
	}
	// clear global key elicit|alias|domain
	delete(s.elicitedGlobal, joinKey("elicit", alias, domain))
	s.elicitMu.Unlock()
	if serviceDebug() {
		log.Printf("[github] elicit cleared for alias=%s domain=%s", alias, domain)
	}
}

// waitForToken blocks until a token is saved for alias/domain (any repo), or context/timeout occurs.
func (s *Service) waitForToken(ctx context.Context, ns, alias, domain, owner, name string, timeout time.Duration) bool {
	if t := s.loadTokenPreferred(ns, alias, domain, owner, name); t != "" {
		return true
	}
	key := s.tokenWaitKey(alias, domain)
	ch := make(chan struct{}, 1)
	s.waitMu.Lock()
	s.waiters[key] = append(s.waiters[key], ch)
	s.waitMu.Unlock()
	if serviceDebug() {
		log.Printf("[github] waitForToken start ns=%s alias=%s domain=%s owner=%s repo=%s timeout=%s", ns, alias, domain, owner, name, timeout)
	}
	// Re-check in case token arrived before registration
	if t := s.loadTokenPreferred(ns, alias, domain, owner, name); t != "" {
		s.notifyToken(alias, domain)
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		if serviceDebug() {
			log.Printf("[github] waitForToken canceled ns=%s alias=%s domain=%s", ns, alias, domain)
		}
		return false
	case <-timer.C:
		if serviceDebug() {
			log.Printf("[github] waitForToken timeout ns=%s alias=%s domain=%s", ns, alias, domain)
		}
		return false
	case <-ch:
		if serviceDebug() {
			log.Printf("[github] waitForToken notified ns=%s alias=%s domain=%s", ns, alias, domain)
		}
		return true
	}
}

// Public methods: ListRepos, ListRepoIssues, ListRepoPRs
func (s *Service) ListRepos(ctx context.Context, in *ListReposInput, prompt func(string)) (*ListReposOutput, error) {
	alias := s.normalizeAlias(in.Account.Alias)
	cli := adapter.New(in.Account.Domain)
	repos, err := withCredentialRetry(ctx, s, alias, in.Account.Domain, prompt, func(token string) ([]adapter.Repo, error) {
		return cli.ListRepos(ctx, token, in.Visibility, in.Affiliation, in.PerPage)
	})
	if err != nil {
		return nil, err
	}
	out := &ListReposOutput{}
	for _, v := range repos {
		out.Repos = append(out.Repos, Repo{ID: v.ID, Name: v.Name, FullName: v.FullName})
	}
	return out, nil
}
func (s *Service) ListRepoIssues(ctx context.Context, in *ListRepoIssuesInput, prompt func(string)) (*ListRepoIssuesOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, alias, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	cli := adapter.New(domain)
	issues, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) ([]adapter.Issue, error) {
		return cli.ListRepoIssues(ctx, token, owner, name, in.State)
	})
	if err != nil {
		return nil, err
	}
	out := &ListRepoIssuesOutput{}
	for _, v := range issues {
		out.Issues = append(out.Issues, Issue{ID: v.ID, Number: v.Number, Title: v.Title, State: v.State})
	}
	return out, nil
}
func (s *Service) ListRepoPRs(ctx context.Context, in *ListRepoPRsInput, prompt func(string)) (*ListRepoPRsOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, alias, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	cli := adapter.New(domain)
	pulls, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) ([]adapter.PullRequest, error) {
		return cli.ListRepoPRs(ctx, token, owner, name, in.State)
	})
	if err != nil {
		return nil, err
	}
	out := &ListRepoPRsOutput{}
	for _, v := range pulls {
		out.Pulls = append(out.Pulls, PullRequest{ID: v.ID, Number: v.Number, Title: v.Title, State: v.State})
	}
	return out, nil
}

// CreateIssue creates a new issue in a repository.
func (s *Service) CreateIssue(ctx context.Context, in *CreateIssueInput, prompt func(string)) (*CreateIssueOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, alias, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	cli := adapter.New(domain)
	issue, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (adapter.Issue, error) {
		return cli.CreateIssue(ctx, token, owner, name, in.Title, in.Body, in.Labels, in.Assignees)
	})
	if err != nil {
		return nil, err
	}
	return &CreateIssueOutput{Issue: Issue{ID: issue.ID, Number: issue.Number, Title: issue.Title, State: issue.State}}, nil
}

// CreatePR opens a pull request.
func (s *Service) CreatePR(ctx context.Context, in *CreatePRInput, prompt func(string)) (*CreatePROutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, alias, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	cli := adapter.New(domain)
	pr, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (adapter.PullRequest, error) {
		return cli.CreatePR(ctx, token, owner, name, in.Title, in.Body, in.Head, in.Base, in.Draft)
	})
	if err != nil {
		return nil, err
	}
	return &CreatePROutput{Pull: PullRequest{ID: pr.ID, Number: pr.Number, Title: pr.Title, State: pr.State}}, nil
}

// AddComment adds a comment to an issue or PR (PR comments use issue comments endpoint).
func (s *Service) AddComment(ctx context.Context, in *AddCommentInput, prompt func(string)) (*AddCommentOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, alias, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	cli := adapter.New(domain)
	cm, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (adapter.Comment, error) {
		return cli.AddComment(ctx, token, owner, name, in.IssueNumber, in.Body)
	})
	if err != nil {
		return nil, err
	}
	return &AddCommentOutput{Comment: Comment{ID: cm.ID, Body: cm.Body, User: cm.User, CreatedAt: cm.CreatedAt}}, nil
}

// ListComments lists comments for an issue or PR.
func (s *Service) ListComments(ctx context.Context, in *ListCommentsInput, prompt func(string)) (*ListCommentsOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, alias, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	cli := adapter.New(domain)
	items, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) ([]adapter.Comment, error) {
		return cli.ListComments(ctx, token, owner, name, in.IssueNumber)
	})
	if err != nil {
		return nil, err
	}
	out := &ListCommentsOutput{}
	for _, v := range items {
		out.Comments = append(out.Comments, Comment{ID: v.ID, Body: v.Body, User: v.User, CreatedAt: v.CreatedAt})
	}
	return out, nil
}

// SearchIssues runs a GitHub issues/PRs search query.
func (s *Service) SearchIssues(ctx context.Context, in *SearchIssuesInput, prompt func(string)) (*SearchIssuesOutput, error) {
	alias := s.normalizeAlias(in.Account.Alias)
	cli := adapter.New(in.Account.Domain)
	issues, err := withCredentialRetry(ctx, s, alias, in.Account.Domain, prompt, func(token string) ([]adapter.Issue, error) {
		return cli.SearchIssues(ctx, token, in.Query, in.PerPage)
	})
	if err != nil {
		return nil, err
	}
	out := &SearchIssuesOutput{}
	for _, it := range issues {
		out.Issues = append(out.Issues, Issue{ID: it.ID, Number: it.Number, Title: it.Title, State: it.State})
	}
	return out, nil
}

// ListRepoPath lists repo directory entries or a single file at the given path and ref.
func (s *Service) ListRepoPath(ctx context.Context, in *ListRepoInput, prompt func(string)) (*ListRepoOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("input is nil")
	}
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo, Ref: in.Ref}
	domain, owner, name, ref, alias, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	if alias == "" {
		// Prefer alias derived from URL owner when that alias already has a token.
		if ns, _ := s.auth.Namespace(ctx); true {
			if ns == "" {
				ns = "default"
			}
			if tok := s.loadTokenPreferred(ns, owner, domain, owner, name); tok != "" {
				alias = owner
			}
		}
		// Try token-based inference next
		if alias == "" {
			if inf, _ := s.inferAlias(ctx, domain, owner, name); inf != "" {
				alias = inf
			}
		}
		// As a last resort, default to owner (so flow can proceed to token resolution/prompt).
		if alias == "" && owner != "" {
			alias = owner
		}
	}
	// Execute with token using the retry helper to enable elicitation if no token exists.
	return withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (*ListRepoOutput, error) {
		// If recursive requested, prefer Git Trees API for performance.
		if in.Recursive {
        // Resolve default branch first if ref empty; if provided ref is invalid, fallback to contents DFS.
        cli := adapter.New(domain)
        ref, err := t.ResolveRef(ctx, cli, token, owner, name, ref)
        if err != nil {
            return nil, err
        }
        if serviceDebug() {
            log.Printf("[github] list: resolved ref=%q domain=%s owner=%s repo=%s path=%q", ref, domain, owner, name, in.Path)
        }
        // Eagerly validate a user-supplied ref; if invalid, switch to default branch to avoid slow DFS.
        if strings.TrimSpace(t.Ref) != "" {
            if err := cli.ValidateRef(ctx, token, owner, name, ref); err != nil {
                if def, derr := cli.GetRepoDefaultBranch(ctx, token, owner, name); derr == nil && def != "" {
                    ref = def
                }
            }
        }
        treeSha, err := cli.GetCommitTreeSHA(ctx, token, owner, name, ref)
        if err != nil {
            // If commit resolution fails on GHE (e.g., 422), fallback to a contents-based recursive walk.
            if serviceDebug() { log.Printf("[github] GetCommitTreeSHA failed for ref=%q: %v; falling back to contents DFS", ref, err) }
            walker := s.makeContentAPI(domain)
            startPath := strings.Trim(strings.TrimPrefix(in.Path, "/"), "/")
            if serviceDebug() { log.Printf("[github] list: DFS start ref=%q path=%q", ref, startPath) }
            // Simple DFS over directories using Contents API
            var out ListRepoOutput
            var stack = []string{startPath}
            visited := map[string]bool{}
            for len(stack) > 0 {
                n := len(stack) - 1
                dir := stack[n]
                stack = stack[:n]
                if visited[dir] { continue }
                visited[dir] = true
                items, werr := walker.ListContents(ctx, token, owner, name, dir, ref)
                if werr != nil {
                    // Retry with default branch if available
                    if def, derr := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name); derr == nil {
                        items, werr = walker.ListContents(ctx, token, owner, name, dir, def)
                        if werr == nil {
                            ref = def
                        }
                    }
                    if werr != nil { return nil, werr }
                }
                for _, it := range items {
                    // Filter by in.Contains/include/exclude later; we need full paths
                    if it.Type == "dir" { stack = append(stack, strings.Trim(strings.TrimPrefix(it.Path, "/"), "/")) }
                    if it.Type == "file" || it.Type == "dir" {
                        if !passIncludeExclude(it.Path, in.Include, in.Exclude) { continue }
                        if c := strings.ToLower(strings.TrimSpace(in.Contains)); c != "" {
                            if !strings.Contains(strings.ToLower(it.Path), c) && !strings.Contains(strings.ToLower(it.Name), c) { continue }
                        }
                        out.Items = append(out.Items, AssetItem{Type: it.Type, Name: pathBase(it.Path), Path: it.Path, Size: it.Size, Sha: it.Sha})
                    }
                }
            }
            return &out, nil
        }
			// Determine if this is a root request (full-tree). If so, try cache by domain/owner/repo.
			startPath := strings.TrimPrefix(in.Path, "/")
			prefix := strings.Trim(startPath, "/")

			var entries []adapter.TreeEntry
			useCache := prefix == ""
			cacheKey := ""
			if useCache {
				cacheKey = s.repoKey(domain, owner, name)
				s.treeMu.RLock()
				cached, ok := s.treeCache[cacheKey]
				s.treeMu.RUnlock()
				if ok {
					if time.Now().Before(cached.expireAt) && len(cached.entries) > 0 {
						entries = cached.entries
					} else {
						// Expired entry: purge eagerly (best-effort)
						s.treeMu.Lock()
						delete(s.treeCache, cacheKey)
						s.treeMu.Unlock()
					}
				}
			}
			// Miss or not using cache: fetch
			if entries == nil {
				fetched, truncated, err := cli.GetTreeRecursive(ctx, token, owner, name, treeSha)
				if err != nil {
					return nil, err
				}
				if truncated {
					return nil, fmt.Errorf("tree listing truncated by API; narrow path or use non-recursive mode")
				}
				entries = fetched
				if useCache {
					s.treeMu.Lock()
					s.treeCache[cacheKey] = treeCacheEntry{
						entries:  append([]adapter.TreeEntry(nil), entries...),
						expireAt: time.Now().Add(30 * time.Minute),
					}
					s.treeMu.Unlock()
				}
			}
			// Filter by path prefix and contains
			contains := strings.ToLower(strings.TrimSpace(in.Contains))
			include := in.Include
			exclude := in.Exclude
			var out ListRepoOutput
			for _, e := range entries {
				if prefix != "" && !strings.HasPrefix(e.Path, prefix+"/") && e.Path != prefix {
					continue
				}
				if contains != "" && !strings.Contains(strings.ToLower(e.Path), contains) && !strings.Contains(strings.ToLower(pathBase(e.Path)), contains) {
					continue
				}
				if !passIncludeExclude(e.Path, include, exclude) {
					continue
				}
        			typ := e.Type
        			if typ == "tree" {
        				typ = "dir"
        			} else if typ == "blob" {
        				typ = "file"
        			}
				out.Items = append(out.Items, AssetItem{Type: typ, Name: pathBase(e.Path), Path: e.Path, Size: e.Size, Sha: e.Sha})
			}
			return &out, nil
		}

        // Non-recursive: single directory via contents API
        cli := s.makeContentAPI(domain)
        startPath := strings.TrimPrefix(in.Path, "/")
        // Resolve ref if empty to avoid GHE default-branch ambiguities
        useRef := strings.TrimSpace(in.Ref)
        if useRef == "" {
            cliRef := adapter.New(domain)
            if def, err := (&GitTarget{Ref: ""}).ResolveRef(ctx, cliRef, token, owner, name, ""); err == nil && def != "" {
                useRef = def
            }
        }
        if serviceDebug() { log.Printf("[github] list: contents ref=%q path=%q", useRef, startPath) }
        items, err := cli.ListContents(ctx, token, owner, name, startPath, useRef)
        if err != nil {
            if def, derr := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name); derr == nil {
                items, err = cli.ListContents(ctx, token, owner, name, startPath, def)
            }
            if err != nil { return nil, err }
        }
		contains := strings.ToLower(strings.TrimSpace(in.Contains))
		include := in.Include
		exclude := in.Exclude
		var out ListRepoOutput
		for _, v := range items {
			if contains != "" && !strings.Contains(strings.ToLower(v.Path), contains) && !strings.Contains(strings.ToLower(v.Name), contains) {
				continue
			}
			if !passIncludeExclude(v.Path, include, exclude) {
				continue
			}
			out.Items = append(out.Items, AssetItem{Type: v.Type, Name: v.Name, Path: v.Path, Size: v.Size, Sha: v.Sha})
		}
		return &out, nil
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func passIncludeExclude(path string, include, exclude []string) bool {
	// Exclude wins
	for _, pat := range exclude {
		if globMatch(pat, path) || globMatch(pat, pathBase(path)) {
			return false
		}
	}
	if len(include) == 0 {
		return true
	}
	for _, pat := range include {
		if globMatch(pat, path) || globMatch(pat, pathBase(path)) {
			return true
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	// Convert ** to a simple contains check when present (coarse but effective for our use)
	if strings.Contains(pattern, "**/") {
		// Remove **/ and fallback to path suffix match
		p := strings.ReplaceAll(pattern, "**/", "")
		return simplePathMatch(p, name)
	}
	return simplePathMatch(pattern, name)
}

func simplePathMatch(pattern, name string) bool {
	// Very basic glob: *.ext and prefix/* patterns
	pattern = strings.ToLower(pattern)
	n := strings.ToLower(name)
	if strings.HasPrefix(pattern, "*") && strings.Count(pattern, "*") == 1 && strings.HasPrefix(pattern, "*.") {
		// *.ext
		suf := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(n, suf)
	}
	if strings.HasSuffix(pattern, "/*") {
		pre := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(n, pre+"/")
	}
	// Fallback contains or exact
	if strings.Contains(pattern, "*") {
		// crude * handling: replace * with empty and check contains of the remainder
		p := strings.ReplaceAll(pattern, "*", "")
		return strings.Contains(n, p)
	}
	return n == pattern || strings.HasSuffix(n, "/"+pattern) || strings.HasPrefix(n, pattern+"/")
}

// DownloadRepoFile fetches raw bytes of a file at path and ref.
func (s *Service) DownloadRepoFile(ctx context.Context, in *DownloadInput, prompt func(string)) (*DownloadOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("input is nil")
	}
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo, Ref: in.Ref}
	domain, owner, name, ref, alias, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	if alias == "" {
		// Prefer alias derived from URL owner when that alias already has a token.
		if ns, _ := s.auth.Namespace(ctx); true {
			if ns == "" {
				ns = "default"
			}
			if tok := s.loadTokenPreferred(ns, owner, domain, owner, name); tok != "" {
				alias = owner
			}
		}
		// Try token-based inference next
		if alias == "" {
			if inf, _ := s.inferAlias(ctx, domain, owner, name); inf != "" {
				alias = inf
			}
		}
		// As a last resort, default to owner
		if alias == "" && owner != "" {
			alias = owner
		}
	}
    cli := s.makeContentAPI(domain)
    data, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) ([]byte, error) {
        // Resolve ref to default if empty using authenticated call
        useRef := strings.TrimSpace(ref)
        if useRef == "" {
            cliRef := adapter.New(domain)
            if def, err := (&GitTarget{Ref: ""}).ResolveRef(ctx, cliRef, token, owner, name, ""); err == nil && def != "" {
                useRef = def
            }
        }
        if serviceDebug() { log.Printf("[github] download: using ref=%q path=%q", useRef, in.Path) }
        p := strings.TrimPrefix(in.Path, "/")
        // First try contents API
        if data, err := cli.GetFileContent(ctx, token, owner, name, p, useRef); err == nil {
            return data, nil
        }
        if serviceDebug() { log.Printf("[github] download: contents failed for ref=%q path=%q; falling back to contents-dir+blob", useRef, p) }
        // Fallback: list parent directory via contents on default branch to obtain file SHA, then fetch blob by SHA
        parent := p
        if idx := strings.LastIndex(parent, "/"); idx >= 0 { parent = parent[:idx] } else { parent = "" }
        def, derr := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name)
        if derr != nil { return nil, derr }
        items, err := cli.ListContents(ctx, token, owner, name, parent, def)
        if err != nil { return nil, err }
        var sha string
        for _, it := range items {
            if it.Path == p && it.Sha != "" { sha = it.Sha; break }
        }
        if sha == "" {
            return nil, fmt.Errorf("get content failed: %s", "sha not found in parent listing on default branch")
        }
        return adapter.New(domain).GetBlob(ctx, token, owner, name, sha)
    })
    if err != nil {
        return nil, err
    }
    // Auto-detect text vs binary. Populate only one of Text or Content.
    if isProbablyText(data) {
        return &DownloadOutput{Text: string(data)}, nil
    }
    return &DownloadOutput{Content: data}, nil
}

// isProbablyText reports whether b looks like UTF-8 text with a low ratio of control characters.
func isProbablyText(b []byte) bool {
    if len(b) == 0 { return true }
    // Treat as text if valid UTF-8 and contains no NUL bytes and few non-printable runes.
    if !utf8.Valid(b) { return false }
    // Sample up to first 4KB to keep it cheap.
    sample := b
    if len(sample) > 4096 { sample = sample[:4096] }
    // Count control runes excluding common whitespace (tab, newline, carriage return).
    var control, total int
    for len(sample) > 0 {
        r, size := utf8.DecodeRune(sample)
        sample = sample[size:]
        total++
        if r == '\n' || r == '\r' || r == '\t' {
            continue
        }
        if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
            control++
            if control > 8 { // a few control chars allowed; above that assume binary
                return false
            }
        }
    }
    return true
}

func (s *Service) normalizeAlias(a string) string { return a }
