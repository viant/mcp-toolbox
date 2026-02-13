package service

import (
	"bytes"
	"context"
	"github.com/viant/afs"
	"io"
	"log"
	"strings"
)

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

func (s *Service) loadToken(ns, alias, domain string) string {
	key := s.tokenKey(ns, alias, domain)
	s.mu.RLock()
	t := s.tokens[key]
	s.mu.RUnlock()
	return t
}

func (s *Service) loadTokenPreferred(ns, alias, domain, owner, name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out string
	var outKey string
	// Try exact alias first
	if owner != "" && name != "" && s.clientID != "" {
		if t := s.tokens[s.tokenKeyRepoOAuth(ns, alias, domain, owner, name, s.clientID)]; t != "" {
			out = t
			outKey = s.tokenKeyRepoOAuth(ns, alias, domain, owner, name, s.clientID)
		}
	}
	if out == "" && owner != "" && name != "" {
		if t := s.tokens[s.tokenKeyRepo(ns, alias, domain, owner, name)]; t != "" {
			out = t
			outKey = s.tokenKeyRepo(ns, alias, domain, owner, name)
		}
	}
	if out == "" && s.clientID != "" {
		if t := s.tokens[s.tokenKeyOAuth(ns, alias, domain, s.clientID)]; t != "" {
			out = t
			outKey = s.tokenKeyOAuth(ns, alias, domain, s.clientID)
		}
	}
	if out == "" {
		if t := s.tokens[s.tokenKey(ns, alias, domain)]; t != "" {
			out = t
			outKey = s.tokenKey(ns, alias, domain)
		}
	}
	// Fallback to canonical alias for domain-wide reuse when alias looks implicit (owner/repo or empty)
	if out == "" {
		a := strings.TrimSpace(alias)
		if a == "" || strings.Contains(a, "/") {
			ca := "default"
			if owner != "" && name != "" && s.clientID != "" {
				if t := s.tokens[s.tokenKeyRepoOAuth(ns, ca, domain, owner, name, s.clientID)]; t != "" {
					out = t
					outKey = s.tokenKeyRepoOAuth(ns, ca, domain, owner, name, s.clientID)
				}
			}
			if out == "" && owner != "" && name != "" {
				if t := s.tokens[s.tokenKeyRepo(ns, ca, domain, owner, name)]; t != "" {
					out = t
					outKey = s.tokenKeyRepo(ns, ca, domain, owner, name)
				}
			}
			if out == "" && s.clientID != "" {
				if t := s.tokens[s.tokenKeyOAuth(ns, ca, domain, s.clientID)]; t != "" {
					out = t
					outKey = s.tokenKeyOAuth(ns, ca, domain, s.clientID)
				}
			}
			if out == "" {
				if t := s.tokens[s.tokenKey(ns, ca, domain)]; t != "" {
					out = t
					outKey = s.tokenKey(ns, ca, domain)
				}
			}
		}
	}
	// Fallback to any alias for same namespace+domain when exact alias not found.
	if out == "" {
		safeNS := safePart(ns)
		safeDomain := safePart(domain)
		// Prefer repo-scoped tokens first.
		if owner != "" && name != "" && s.clientID != "" {
			for k, v := range s.tokens {
				parts := strings.Split(k, "|")
				if len(parts) == 6 && parts[0] == safeNS && parts[2] == safeDomain &&
					parts[3] == safePart(owner) && parts[4] == safePart(name) && strings.HasPrefix(parts[5], "oauth:") {
					if v != "" {
						out = v
						outKey = k
						break
					}
				}
			}
		}
		if out == "" && owner != "" && name != "" {
			for k, v := range s.tokens {
				parts := strings.Split(k, "|")
				if len(parts) == 5 && parts[0] == safeNS && parts[2] == safeDomain &&
					parts[3] == safePart(owner) && parts[4] == safePart(name) {
					if v != "" {
						out = v
						outKey = k
						break
					}
				}
			}
		}
		if out == "" && s.clientID != "" {
			for k, v := range s.tokens {
				parts := strings.Split(k, "|")
				if len(parts) == 4 && parts[0] == safeNS && parts[2] == safeDomain && strings.HasPrefix(parts[3], "oauth:") {
					if v != "" {
						out = v
						outKey = k
						break
					}
				}
			}
		}
		if out == "" {
			for k, v := range s.tokens {
				parts := strings.Split(k, "|")
				if len(parts) == 3 && parts[0] == safeNS && parts[2] == safeDomain {
					if v != "" {
						out = v
						outKey = k
						break
					}
				}
			}
		}
	}
	if out != "" && outKey != "" {
		// Notify in logs when alias fallback is used.
		parts := strings.Split(outKey, "|")
		if len(parts) >= 2 && parts[1] != safePart(alias) {
			log.Printf("github token: alias fallback ns=%s domain=%s requested_alias=%s used_alias=%s", ns, domain, alias, parts[1])
		}
	}
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
		if shouldMirrorAlias(alias) {
			s.tokens[s.tokenKeyRepoOAuth(ns, "default", domain, owner, name, s.clientID)] = token
		}
	} else {
		s.tokens[s.tokenKeyRepo(ns, alias, domain, owner, name)] = token
		if shouldMirrorAlias(alias) {
			s.tokens[s.tokenKeyRepo(ns, "default", domain, owner, name)] = token
		}
	}
	s.mu.Unlock()
}
func (s *Service) saveTokenDomain(ns, alias, domain, token string, oauthKey bool) {
	s.mu.Lock()
	if oauthKey && s.clientID != "" {
		s.tokens[s.tokenKeyOAuth(ns, alias, domain, s.clientID)] = token
		if shouldMirrorAlias(alias) {
			s.tokens[s.tokenKeyOAuth(ns, "default", domain, s.clientID)] = token
		}
	} else {
		s.tokens[s.tokenKey(ns, alias, domain)] = token
		if shouldMirrorAlias(alias) {
			s.tokens[s.tokenKey(ns, "default", domain)] = token
		}
	}
	s.mu.Unlock()
}
func (s *Service) clearToken(ns, alias, domain string) {
	key := s.tokenKey(ns, alias, domain)
	s.mu.Lock()
	delete(s.tokens, key)
	s.mu.Unlock()
}

func shouldMirrorAlias(alias string) bool {
	a := strings.TrimSpace(alias)
	return a != "" && a != "default" && strings.Contains(a, "/")
}

func (s *Service) tokenURL(ns, alias, domain, owner, repo string) string {
	base := s.secretsBase
	if base == "" {
		return ""
	}
	if domain == "" {
		domain = "github.com"
	}
	parts := []string{base, "github", safePart(ns), safePart(alias), safePart(domain)}
	if owner != "" && repo != "" {
		parts = append(parts, safePart(owner), safePart(repo))
	}
	parts = append(parts, "token")
	return strings.Join(parts, "/")
}

func (s *Service) persistToken(ctx context.Context, ns, alias, domain, owner, repo, token string) {
	if s.secretsBase == "" || token == "" {
		return
	}
	if url := s.tokenURL(ns, alias, domain, owner, repo); url != "" {
		_ = afs.New().Upload(ctx, url, 0o600, bytes.NewReader([]byte(token)))
	}
}

func (s *Service) loadTokenFromSecrets(ctx context.Context, ns, alias, domain, owner, repo string) string {
	if s.secretsBase == "" {
		return ""
	}
	tryURLs := []string{}
	if owner != "" && repo != "" {
		tryURLs = append(tryURLs, s.tokenURL(ns, alias, domain, owner, repo))
	}
	tryURLs = append(tryURLs, s.tokenURL(ns, alias, domain, "", ""))
	// Fallback to canonical alias 'default' when alias implicit
	a := strings.TrimSpace(alias)
	if a == "" || strings.Contains(a, "/") {
		if owner != "" && repo != "" {
			tryURLs = append(tryURLs, s.tokenURL(ns, "default", domain, owner, repo))
		}
		tryURLs = append(tryURLs, s.tokenURL(ns, "default", domain, "", ""))
	}
	for _, u := range tryURLs {
		if u == "" {
			continue
		}
		rc, err := afs.New().OpenURL(ctx, u)
		if err == nil && rc != nil {
			data, _ := io.ReadAll(rc)
			_ = rc.Close()
			if len(data) > 0 {
				return string(data)
			}
		}
	}
	return ""
}

// Cross-namespace scan for a usable token. Preference mirrors loadTokenPreferred.
func (s *Service) loadTokenPreferredAnyNS(alias, domain, owner, name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	safeAlias := safePart(alias)
	safeDomain := safePart(domain)
	// When owner/name empty, search domain-level tokens across namespaces first.
	if owner == "" && name == "" {
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
