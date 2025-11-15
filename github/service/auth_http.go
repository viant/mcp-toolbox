package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"
	// embed OOB HTML template
	_ "embed"

	"github.com/google/uuid"
	"github.com/viant/mcp-toolbox/github/adapter"
	oob "github.com/viant/mcp/server/oob"
)

// RegisterHTTP registers GitHub auth-related HTTP handlers on the provided mux.
// This file isolates HTTP wiring from the core service to simplify future refactors.
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
			if d, err := s.ns.Namespace(r.Context()); err == nil {
				ns = d.Name
			}
		}
		if ns == "" {
			http.Error(w, "namespace required", http.StatusBadRequest)
			return
		}
		type row struct{ UUID, Alias, Namespace, UserCode, VerifyURL string }
		out := make([]row, 0)
		if s.oobMgr != nil {
			pendings, _ := s.oobMgr.Store.ListNamespace(r.Context(), ns)
			for _, p := range pendings {
				out = append(out, row{UUID: p.ID, Alias: p.Alias, Namespace: p.Namespace, UserCode: p.Data.UserCode, VerifyURL: p.Data.VerifyURL})
			}
		} else {
			list := s.pending.ListNamespace(ns)
			for _, v := range list {
				out = append(out, row{UUID: v.UUID, Alias: v.Alias, Namespace: v.Namespace, UserCode: v.UserCode, VerifyURL: v.VerifyURL})
			}
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
			if d, err := s.ns.Namespace(r.Context()); err == nil {
				ns = d.Name
			}
		}
		if ns == "" {
			http.Error(w, "namespace required", http.StatusBadRequest)
			return
		}
		var cleared []string
		if s.oobMgr != nil {
			ids, _ := s.oobMgr.Store.ClearNamespace(r.Context(), ns)
			cleared = ids
		} else {
			cleared = s.pending.ClearNamespace(ns)
		}
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
		UUID        string `json:"uuid,omitempty"`
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
		uuidStr := r.URL.Query().Get("uuid")
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
		if uuidStr == "" {
			uuidStr = rb.UUID
		}
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
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
			}
		}
		if token == "" {
			http.Error(w, "access token missing", http.StatusBadRequest)
			return
		}
		if domain == "" {
			domain = "github.com"
		}
		// Validate credentials before saving
		cli := adapter.New(domain)
		if err := cli.ValidateToken(r.Context(), token); err != nil {
			if errors.Is(err, adapter.ErrUnauthorized) {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
				return
			}
			http.Error(w, "credential validation failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		dsc, _ := s.ns.Namespace(r.Context())
		ns := dsc.Name
		if ns == "" {
			ns = "default"
		}
		// If uuid corresponds to a pending auth, prefer its namespace for binding
		if u := strings.TrimSpace(uuidStr); u != "" {
			if s.oobMgr != nil {
				if p, ok, _ := s.oobMgr.Store.Get(r.Context(), u); ok && p.Namespace != "" {
					ns = p.Namespace
				}
			} else if pend, ok := s.pending.Get(u); ok && pend != nil && pend.Namespace != "" {
				ns = pend.Namespace
			}
		}
		if owner != "" && repo != "" {
			s.saveTokenRepo(ns, alias, domain, owner, repo, token, oauthKey)
			s.persistToken(r.Context(), ns, alias, domain, owner, repo, token)
		}
		// Always save domain-level token for broad reuse across repos
		s.saveTokenDomain(ns, alias, domain, token, oauthKey)
		s.persistToken(r.Context(), ns, alias, domain, "", "", token)
		// If alias looks implicit (owner/repo or empty), also persist under canonical alias 'default'
		if a := strings.TrimSpace(alias); a == "" || strings.Contains(a, "/") {
			s.saveTokenDomain(ns, "default", domain, token, oauthKey)
			s.persistToken(r.Context(), ns, "default", domain, "", "", token)
			if owner != "" && repo != "" {
				s.saveTokenRepo(ns, "default", domain, owner, repo, token, oauthKey)
				s.persistToken(r.Context(), ns, "default", domain, owner, repo, token)
			}
		}
		s.clearElicitedAll(alias, domain)
		s.notifyToken(ns, alias, domain)
		if uuidStr != "" {
			s.pending.Remove(uuidStr)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}
}

// DeviceStartHandler initiates device authorization and returns URL+code without blocking for completion.
func (s *Service) DeviceStartHandler() http.HandlerFunc {
	type reqBody struct{ Alias, Domain string }
	type dcResp struct {
		DeviceCode, UserCode, VerificationURI string
		ExpiresIn, Interval                   int
	}
	type respBody struct {
		UUID, OOBUrl, VerifyURL, UserCode string
		ExpiresIn, Interval               int
	}
	type tokResp struct {
		AccessToken, Error string `json:"access_token","error"`
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
		// Record device login details via OOB manager if available; otherwise fallback to local pending.
		var id, oobURL string
		if s.oobMgr != nil {
			exp := time.Now().Add(time.Duration(dcr.ExpiresIn) * time.Second)
			var err2 error
			id, oobURL, err2 = s.oobMgr.Create(r.Context(), oob.Spec[AuthOOBData]{
				Kind:      "github_device",
				Alias:     alias,
				Resource:  host,
				ExpiresAt: exp,
				Data:      AuthOOBData{Alias: alias, Domain: host, VerifyURL: dcr.VerificationURI, UserCode: dcr.UserCode},
			})
			if err2 != nil {
				id = ""
			}
		}
		if id == "" {
			dsc, _ := s.ns.Namespace(r.Context())
			ns := dsc.Name
			id = uuid.New().String()
			s.pending.Put(&PendingAuth{UUID: id, Alias: alias, Namespace: ns, UserCode: dcr.UserCode, VerifyURL: dcr.VerificationURI})
			oobURL = strings.TrimRight(s.baseURL, "/") + "/github/auth/device/" + id
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(respBody{UUID: id, OOBUrl: oobURL, VerifyURL: dcr.VerificationURI, UserCode: dcr.UserCode, ExpiresIn: dcr.ExpiresIn, Interval: dcr.Interval})
		// Start background polling to exchange device_code for access token
		fallbackNS := s.Namespace(r.Context())
		go func(ctx context.Context, alias, domain, deviceCode, pendingID, fallbackNS string, interval int) {
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
					if s.oobMgr != nil && pendingID != "" {
						if p, ok, _ := s.oobMgr.Store.Get(ctx, pendingID); ok && p.Namespace != "" {
							ns2 = p.Namespace
						}
					}
					if ns2 == "" {
						ns2 = fallbackNS
					}
					s.saveToken(ns2, alias, domain, tr.AccessToken)
					s.clearElicitedAll(alias, domain)
					s.notifyToken(ns2, alias, domain)
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
		}(r.Context(), alias, domain, dcr.DeviceCode, id, fallbackNS, dcr.Interval)
	}
}

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
		if u := strings.TrimSpace(r.URL.Query().Get("uuid")); u != "" {
			if s.oobMgr != nil {
				if p, ok, _ := s.oobMgr.Store.Get(r.Context(), u); ok && p.Namespace != "" {
					ns = p.Namespace
				}
			} else if pend, ok := s.pending.Get(u); ok && pend != nil && pend.Namespace != "" {
				ns = pend.Namespace
			}
		}
		has := s.loadTokenPreferred(ns, alias, domain, owner, repo) != ""
		if !has {
			if u := strings.TrimSpace(r.URL.Query().Get("uuid")); u != "" {
				if s.loadTokenPreferredAnyNS(alias, domain, owner, repo) != "" {
					has = true
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"hasToken": has})
	}
}

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
		}
		owner, name := parts[1], parts[2]
		ns, _ := s.auth.Namespace(r.Context())
		if ns == "" {
			ns = "default"
		}
		if u := strings.TrimSpace(r.URL.Query().Get("uuid")); u != "" {
			if s.oobMgr != nil {
				if p, ok, _ := s.oobMgr.Store.Get(r.Context(), u); ok && p.Namespace != "" {
					ns = p.Namespace
				}
			} else if pend, ok := s.pending.Get(u); ok && pend != nil && pend.Namespace != "" {
				ns = pend.Namespace
			}
		}
		token := s.loadTokenPreferred(ns, alias, domain, owner, name)
		if token == "" {
			http.Error(w, "no token for alias/domain", http.StatusUnauthorized)
			return
		}
		// Detect SSO required by probing repo endpoint directly to inspect headers
		apiBase := "https://api.github.com"
		if domain != "" && domain != "github.com" {
			apiBase = "https://" + domain + "/api/v3"
		}
		repoURL := fmt.Sprintf("%s/repos/%s/%s", apiBase, owner, name)
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, repoURL, nil)
		req.Header.Set("Authorization", s.authBasic(token))
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp != nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusForbidden {
				sso := resp.Header.Get("X-GitHub-SSO")
				if strings.Contains(strings.ToLower(sso), "required") {
					ssoURL := ""
					if idx := strings.Index(strings.ToLower(sso), "url="); idx >= 0 {
						seg := sso[idx+4:]
						if i := strings.Index(seg, ";"); i >= 0 {
							seg = seg[:i]
						}
						ssoURL = strings.Trim(seg, " ")
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "ssoRequired": true, "ssoUrl": ssoURL})
					return
				}
			}
		}
		// Otherwise, return default branch to confirm access
		cli := adapter.New(domain)
		def, err := cli.GetRepoDefaultBranch(r.Context(), token, owner, name)
		if err != nil {
			http.Error(w, "verify: default branch: "+err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "defaultBranch": def})
	}
}

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
		// Device code hint from pending, if present
		deviceInitial := ""
		if uuid != "" {
			if s.oobMgr != nil {
				if p, ok := oob.FromContext[AuthOOBData](r.Context()); ok {
					if p.Data.VerifyURL != "" && p.Data.UserCode != "" {
						deviceInitial = fmt.Sprintf("Open <a href=\"%s\" target=\"_blank\" rel=\"noopener\">%s</a> and enter code <code>%s</code>.", html.EscapeString(p.Data.VerifyURL), html.EscapeString(p.Data.VerifyURL), html.EscapeString(p.Data.UserCode))
					}
				} else if pend, ok, _ := s.oobMgr.Store.Get(r.Context(), uuid); ok {
					if pend.Data.VerifyURL != "" && pend.Data.UserCode != "" {
						deviceInitial = fmt.Sprintf("Open <a href=\"%s\" target=\"_blank\" rel=\"noopener\">%s</a> and enter code <code>%s</code>.", html.EscapeString(pend.Data.VerifyURL), html.EscapeString(pend.Data.VerifyURL), html.EscapeString(pend.Data.UserCode))
					}
				}
			} else if pend, ok := s.pending.Get(uuid); ok && pend != nil {
				deviceInitial = fmt.Sprintf("Open <a href=\"%s\" target=\"_blank\" rel=\"noopener\">%s</a> and enter code <code>%s</code>.", html.EscapeString(pend.VerifyURL), html.EscapeString(pend.VerifyURL), html.EscapeString(pend.UserCode))
			}
		}

		repourl := r.URL.Query().Get("url")
		htmlTmpl := oobPageHTML
		repl := strings.NewReplacer(
			"{{ALIAS}}", html.EscapeString(alias),
			"{{DOMAIN}}", html.EscapeString(host),
			"{{BASE}}", html.EscapeString(base),
			"{{DEVICE}}", deviceInitial,
			"{{REPOURL}}", html.EscapeString(repourl),
			"{{UUID}}", html.EscapeString(uuid),
		)
		htmlPage := repl.Replace(htmlTmpl)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, htmlPage)
	}
}

//go:embed assets/github_oob.html
var oobPageHTML string

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
