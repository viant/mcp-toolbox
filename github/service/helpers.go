package service

import (
    "context"
    "errors"
    "fmt"
    "os"
    "strings"
    "github.com/viant/mcp-toolbox/github/adapter"
)

// withCredentialRetry uses domain-level token for non-repo operations.
func withCredentialRetry[T any](ctx context.Context, svc *Service, alias, domain string, prompt func(string), call func(token string) (T, error)) (T, error) {
	var zero T
	ns, _ := svc.auth.Namespace(ctx)
	if ns == "" {
		ns = "default"
	}
	token := svc.loadToken(ns, alias, domain)
	if token == "" {
		if prompt != nil {
			// Elicit once and wait briefly for token to arrive
			svc.maybeElicitOnce(ctx, alias, domain, "", "", prompt)
			if svc.waitForToken(ctx, ns, alias, domain, "", "", svc.WaitTimeout()) {
				token = svc.loadToken(ns, alias, domain)
				if token == "" {
					token = svc.loadTokenPreferredAnyNS(alias, domain, "", "")
				}
			}
		}
		if token == "" {
			return zero, fmt.Errorf("no token for alias=%s domain=%s; provide token via OOB or use /github/auth/start explicitly", alias, domain)
		}
	}
    if strings.ToLower(strings.TrimSpace(os.Getenv("GITHUB_MCP_DEBUG"))) != "" {
        fmt.Printf("[github] invoking call with domain token alias=%s domain=%s\n", alias, domain)
    }
    out, err := call(token)
	if err == nil {
		return out, nil
	}
	if errors.Is(err, adapter.ErrUnauthorized) {
		return zero, fmt.Errorf("unauthorized for alias=%s domain=%s; token invalid or insufficient scope", alias, domain)
	}
	return zero, err
}

// withRepoCredentialRetry prefers repo-level secret, falling back to domain-level.
func withRepoCredentialRetry[T any](ctx context.Context, svc *Service, alias, domain, owner, name string, prompt func(string), call func(token string) (T, error)) (T, error) {
	var zero T
	ns, _ := svc.auth.Namespace(ctx)
	if ns == "" {
		ns = "default"
	}
	token := svc.loadTokenPreferred(ns, alias, domain, owner, name)
	if token == "" {
		if prompt != nil {
			svc.maybeElicitOnce(ctx, alias, domain, owner, name, prompt)
			if svc.waitForToken(ctx, ns, alias, domain, owner, name, svc.WaitTimeout()) {
				token = svc.loadTokenPreferred(ns, alias, domain, owner, name)
				if token == "" {
					token = svc.loadTokenPreferredAnyNS(alias, domain, owner, name)
				}
			}
		}
		if token == "" {
			return zero, fmt.Errorf("no token for alias=%s domain=%s; provide token via OOB or /github/auth/token", alias, domain)
		}
	}
    if strings.ToLower(strings.TrimSpace(os.Getenv("GITHUB_MCP_DEBUG"))) != "" {
        fmt.Printf("[github] invoking call with repo token alias=%s domain=%s owner=%s repo=%s\n", alias, domain, owner, name)
    }
    out, err := call(token)
	if err == nil {
		return out, nil
	}
	if errors.Is(err, adapter.ErrUnauthorized) {
		return zero, fmt.Errorf("unauthorized for alias=%s domain=%s owner=%s repo=%s; token invalid or insufficient scope", alias, domain, owner, name)
	}
	return zero, err
}
