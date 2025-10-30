package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/viant/mcp-toolbox/github/adapter"
)

// GitTarget encapsulates repo identity (url/domain/owner/name), revision (ref), and auth (alias via Account).
type GitTarget struct {
	URL     string  `json:"url,omitempty" description:"encapsulates repo identity https://domain/owner/name"`
	Account Account `json:"account,omitempty" internal:"true"`
	Repo    RepoRef `json:"repo,omitempty" internal:"true"`
	Ref     string  `json:"ref,omitempty"`
}

// Init parses URL first (if provided) and prefers values from the URL over explicit fields.
// It returns normalized domain, owner, name, ref, alias.
func (t *GitTarget) Init(s *Service) (domain, owner, name, ref, alias string, err error) {
	// Prefer URL when provided
	if u := strings.TrimSpace(t.URL); u != "" {
		// strip scheme if present
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			if p := strings.Index(u, "://"); p > 0 {
				u = u[p+3:]
			}
		}
		parts := strings.Split(strings.Trim(u, "/"), "/")
		if len(parts) < 3 {
			return "", "", "", "", "", fmt.Errorf("invalid url; expected domain/owner/repo")
		}
		domain = parts[0]
		owner = parts[1]
		name = strings.TrimSuffix(parts[2], ".git")
	} else {
		// Fallback to explicit fields
		domain = t.Account.Domain
		owner = t.Repo.Owner
		name = t.Repo.Name
	}
	ref = strings.TrimSpace(t.Ref)
	alias = s.normalizeAlias(t.Account.Alias)
	if owner == "" || name == "" {
		return "", "", "", "", "", fmt.Errorf("repo.owner and repo.name are required (or provide url)")
	}
	return domain, owner, name, ref, alias, nil
}

// ResolveRef returns a usable ref, resolving the default branch if ref is empty.
func (t *GitTarget) ResolveRef(ctx context.Context, cli *adapter.Client, token, owner, name, ref string) (string, error) {
	r := strings.TrimSpace(ref)
	if r != "" {
		return r, nil
	}
	def, err := cli.GetRepoDefaultBranch(ctx, token, owner, name)
	if err != nil {
		return "", err
	}
	return def, nil
}

// GetAlias returns the effective alias for repo-scoped operations using only target data.
// Order of precedence:
// 1) Explicit account.alias if provided.
// 2) If exactly one stored alias has a token for this repo, use that alias (inference).
// 3) Default to "owner/repo" derived from the target.
func (t *GitTarget) GetAlias(ctx context.Context, s *Service) (string, error) {
	domain, owner, name, _, alias, err := t.Init(s)
	if err != nil {
		return "", err
	}
	if alias != "" {
		return alias, nil
	}
	if owner == "" || name == "" {
		return "", nil
	}
	if inf, _ := s.inferAlias(ctx, domain, owner, name); inf != "" {
		return inf, nil
	}
	return owner + "/" + name, nil
}
