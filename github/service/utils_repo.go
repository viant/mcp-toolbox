package service

import (
	"context"
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
	// Minimal shim: no inference, return empty alias and no candidates.
	return "", nil
}
