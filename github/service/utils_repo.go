package service

import (
	"context"
	"strings"
)

// repoKey builds a cache key for a repository scoped to domain/owner/name.
func (s *Service) repoKey(ns, domain, owner, name string) string {
	if domain == "" {
		domain = "github.com"
	}
	if ns == "" {
		ns = "default"
	}
	return ns + "|" + domain + "|" + owner + "|" + name
}

// inferAlias tries to pick an alias automatically when caller omitted it.
func (s *Service) inferAlias(ctx context.Context, domain, owner, name string) (string, []string) {
	desc, _ := s.ns.Namespace(ctx)
	ns := desc.Name
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
