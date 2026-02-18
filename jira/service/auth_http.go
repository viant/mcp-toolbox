package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	// embed OOB HTML template
	_ "embed"
)

// RegisterHTTP registers Jira OOB auth handlers.
func (s *Service) RegisterHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/jira/auth/oob", s.OOBHandler())
	mux.HandleFunc("/jira/auth/token", s.TokenIngestHandler())
	mux.HandleFunc("/jira/auth/check", s.TokenCheckHandler())
	mux.HandleFunc("/jira/auth/verify", s.VerifyHandler())
}

// OOBHandler renders a simple HTML to paste Jira email + token.
func (s *Service) OOBHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		alias := strings.TrimSpace(r.URL.Query().Get("alias"))
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		if alias == "" {
			alias = "default"
		}
		if domain == "" {
			domain = s.defaultDomain()
		}
		base := strings.TrimRight(s.baseURL, "/")
		repl := strings.NewReplacer(
			"{{ALIAS}}", html.EscapeString(alias),
			"{{DOMAIN}}", html.EscapeString(domain),
			"{{BASE}}", html.EscapeString(base),
		)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, repl.Replace(oobPageHTML))
	}
}

// TokenIngestHandler accepts Authorization or JSON and stores for ns|alias|domain.
func (s *Service) TokenIngestHandler() http.HandlerFunc {
	type req struct {
		Alias       string `json:"alias"`
		Domain      string `json:"domain"`
		Email       string `json:"email"`
		AccessToken string `json:"access_token"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		alias := strings.TrimSpace(r.URL.Query().Get("alias"))
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		var rb req
		if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "application/json") {
			_ = json.NewDecoder(r.Body).Decode(&rb)
		}
		if alias == "" {
			alias = strings.TrimSpace(rb.Alias)
		}
		if alias == "" {
			http.Error(w, "alias required", http.StatusBadRequest)
			return
		}
		if domain == "" {
			domain = strings.TrimSpace(rb.Domain)
		}
		if domain == "" {
			domain = s.defaultDomain()
		}
		domain = normalizeDomain(domain)

		email := strings.TrimSpace(rb.Email)
		token := strings.TrimSpace(rb.AccessToken)
		if auth := r.Header.Get("Authorization"); auth != "" {
			e, t := parseAuthHeaderEmailToken(auth)
			if token == "" && t != "" {
				token = t
			}
			if email == "" && e != "" {
				email = e
			}
		}
		if email == "" || token == "" {
			http.Error(w, "missing email or token", http.StatusBadRequest)
			return
		}
		ns, _ := s.auth.Namespace(r.Context())
		if ns == "" {
			ns = "default"
		}
		key := ns + "|" + alias + "|" + domain
		s.mu.Lock()
		s.tokens[key] = token
		s.emails[key] = email
		s.mu.Unlock()
		// Clear any cached client
		s.mu.Lock()
		delete(s.clients, ns+"|"+alias)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}
}

func (s *Service) TokenCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		alias := strings.TrimSpace(r.URL.Query().Get("alias"))
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		if alias == "" {
			alias = "default"
		}
		if domain == "" {
			domain = s.defaultDomain()
		}
		domain = normalizeDomain(domain)
		ns, _ := s.auth.Namespace(r.Context())
		if ns == "" {
			ns = "default"
		}
		key := ns + "|" + alias + "|" + domain
		s.mu.RLock()
		_, okTok := s.tokens[key]
		_, okEmail := s.emails[key]
		s.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"hasToken": okTok && okEmail})
	}
}

// VerifyHandler validates Jira credentials by calling /myself.
func (s *Service) VerifyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		alias := strings.TrimSpace(r.URL.Query().Get("alias"))
		domain := strings.TrimSpace(r.URL.Query().Get("domain"))
		if alias == "" {
			alias = "default"
		}
		if domain == "" {
			domain = s.defaultDomain()
		}
		domain = normalizeDomain(domain)
		ns, _ := s.auth.Namespace(r.Context())
		if ns == "" {
			ns = "default"
		}
		key := ns + "|" + alias + "|" + domain
		s.mu.RLock()
		token := s.tokens[key]
		email := s.emails[key]
		s.mu.RUnlock()
		if token == "" || email == "" {
			http.Error(w, "no token for alias/domain", http.StatusUnauthorized)
			return
		}
		acct := Account{BaseURL: domain, Email: email, Token: token}
		if !strings.HasPrefix(acct.BaseURL, "http") {
			acct.BaseURL = "https://" + acct.BaseURL
		}
		if _, err := url.Parse(acct.BaseURL); err != nil {
			http.Error(w, "invalid baseURL: "+err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := s.jiraGET(r.Context(), acct, "/rest/api/3/myself", ""); err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}
}

func normalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		if u, err := url.Parse(domain); err == nil && u.Host != "" {
			return u.Host
		}
	}
	if u, err := url.Parse("https://" + domain); err == nil && u.Host != "" {
		return u.Host
	}
	return domain
}

func (s *Service) defaultDomain() string {
	if strings.TrimSpace(s.baseURL) == "" {
		return ""
	}
	u, err := url.Parse(s.baseURL)
	if err != nil {
		return ""
	}
	return u.Host
}

func parseAuthHeaderEmailToken(header string) (string, string) {
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", ""
	}
	scheme, val := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
	switch scheme {
	case "bearer":
		return "", val
	case "basic":
		dec, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return "", ""
		}
		creds := string(dec)
		if i := strings.IndexByte(creds, ':'); i != -1 {
			return creds[:i], creds[i+1:]
		}
		return "", creds
	}
	return "", ""
}

//go:embed assets/jira_oob.html
var oobPageHTML string
