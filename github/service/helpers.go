package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/viant/mcp-toolbox/github/adapter"
	"time"
)

// withCredentialRetry uses domain-level token for non-repo operations.
func withCredentialRetry[T any](ctx context.Context, svc *Service, alias, domain string, prompt func(string), call func(token string) (T, error)) (T, error) {
	var zero T
	ns, _ := svc.auth.Namespace(ctx)
	if ns == "" {
		ns = "default"
	}
	// Normalize alias/domain to align waiter and notifier keys
	aliasEff := svc.normalizeAlias(alias)
	if aliasEff == "" {
		aliasEff = "default"
	}
	domainEff := domain
	if domainEff == "" {
		domainEff = "github.com"
	}

	token := svc.loadToken(ns, aliasEff, domainEff)
	if token == "" {
		if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, "", ""); t != "" {
			token = t
			// hydrate memory for future calls
			svc.saveToken(ns, aliasEff, domainEff, token)
		}
	}
	if token == "" {
		if prompt != nil {
			// Elicit once and wait briefly for token to arrive
			svc.maybeElicitOnce(ctx, aliasEff, domainEff, "", "", prompt)
			// Bound wait by context deadline when present
			wait := svc.WaitTimeout()
			if dl, ok := ctx.Deadline(); ok {
				if d := time.Until(dl) - 500*time.Millisecond; d > 0 && d < wait {
					wait = d
				} else if d <= 0 {
					wait = 0
				}
			}
			if wait > 0 && svc.waitForToken(ctx, ns, aliasEff, domainEff, "", "", wait) {
				token = svc.loadToken(ns, aliasEff, domainEff)
				// Only allow cross-namespace fallback when operating in the shared default namespace.
				if token == "" && ns == "default" {
					token = svc.loadTokenPreferredAnyNS(aliasEff, domainEff, "", "")
				}
			}
		}
		if token == "" {
			return zero, fmt.Errorf("no token for alias=%s domain=%s; provide token via OOB or use /github/auth/start explicitly", aliasEff, domainEff)
		}
	}
	// debug logging removed
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
	// Normalize alias/domain to align waiter and notifier keys
	aliasEff := svc.normalizeAlias(alias)
	if aliasEff == "" {
		aliasEff = "default"
	}
	domainEff := domain
	if domainEff == "" {
		domainEff = "github.com"
	}

	token := svc.loadTokenPreferred(ns, aliasEff, domainEff, owner, name)
	if token == "" {
		if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, owner, name); t != "" {
			token = t
			// hydrate memory
			svc.saveTokenRepo(ns, aliasEff, domainEff, owner, name, token, false)
		}
	}
	if token == "" {
		if prompt != nil {
			svc.maybeElicitOnce(ctx, aliasEff, domainEff, owner, name, prompt)
			// Bound wait by context deadline when present
			wait := svc.WaitTimeout()
			if dl, ok := ctx.Deadline(); ok {
				if d := time.Until(dl) - 500*time.Millisecond; d > 0 && d < wait {
					wait = d
				} else if d <= 0 {
					wait = 0
				}
			}
			if wait > 0 && svc.waitForToken(ctx, ns, aliasEff, domainEff, owner, name, wait) {
				token = svc.loadTokenPreferred(ns, aliasEff, domainEff, owner, name)
				// Only allow cross-namespace fallback when operating in the shared default namespace.
				if token == "" && ns == "default" {
					token = svc.loadTokenPreferredAnyNS(aliasEff, domainEff, owner, name)
				}
			}
		}
		if token == "" {
			return zero, fmt.Errorf("no token for alias=%s domain=%s; provide token via OOB or /github/auth/token", aliasEff, domainEff)
		}
	}
	// debug logging removed
	out, err := call(token)
	if err == nil {
		return out, nil
	}
	if errors.Is(err, adapter.ErrUnauthorized) {
		return zero, fmt.Errorf("unauthorized for alias=%s domain=%s owner=%s repo=%s; token invalid or insufficient scope", alias, domain, owner, name)
	}
	return zero, err
}
