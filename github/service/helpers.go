package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/viant/mcp-toolbox/github/adapter"
	"time"
)

func sleepWithCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func backoff(attempt int) time.Duration {
	// 0:0ms, 1:500ms, 2:1s, 3:2s, 4:4s (cap at 4s)
	if attempt <= 0 {
		return 0
	}
	d := 500 * time.Millisecond
	for i := 1; i < attempt; i++ {
		d *= 2
		if d > 4*time.Second {
			d = 4 * time.Second
			break
		}
	}
	return d
}

// withCredentialRetry uses domain-level token for non-repo operations.
func withCredentialRetry[T any](ctx context.Context, svc *Service, alias, domain string, prompt func(string), call func(token string) (T, error)) (T, error) {
	var zero T
	ns := svc.Namespace(ctx)
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
			// debug logs removed
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
			// debug logs removed
		}
		if token == "" {
			return zero, fmt.Errorf("no token for alias=%s domain=%s; provide token via OOB or use /github/auth/start explicitly", aliasEff, domainEff)
		}
	}
	// Call with limited retry on rate limiting
	var out T
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		out, err = call(token)
		if err == nil {
			return out, nil
		}
		if errors.Is(err, adapter.ErrRateLimited) && sleepWithCtx(ctx, backoff(attempt)) {
			continue
		}
		break
	}
	if errors.Is(err, adapter.ErrUnauthorized) || errors.Is(err, adapter.ErrBadCredentials) {
		return zero, fmt.Errorf("unauthorized for alias=%s domain=%s; token invalid or insufficient scope", alias, domain)
	}
	return zero, err
}

// withRepoCredentialRetry tries domain-level credentials first; on unauthorized, falls back to repo-level.
func withRepoCredentialRetry[T any](ctx context.Context, svc *Service, alias, domain, owner, name string, prompt func(string), call func(token string) (T, error)) (T, error) {
	var zero T
	ns := svc.Namespace(ctx)
	cid := CID(ctx)
	// Normalize alias/domain to align waiter and notifier keys
	aliasEff := svc.normalizeAlias(alias)
	if aliasEff == "" {
		aliasEff = "default"
	}
	domainEff := domain
	if domainEff == "" {
		domainEff = "github.com"
	}

	fmt.Printf("[GITHUB] AUTH cid=%s ns=%s alias=%s domain=%s owner=%s repo=%s enter\n", cid, ns, aliasEff, domainEff, owner, name)
	// Load domain-level first (including canonical alias fallback), then repo-level
	domainTok := svc.loadTokenPreferred(ns, aliasEff, domainEff, "", "")
	if domainTok == "" {
		if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, "", ""); t != "" {
			domainTok = t
			svc.saveTokenDomain(ns, aliasEff, domainEff, domainTok, false)
		}
	}
	repoTok := svc.loadTokenPreferred(ns, aliasEff, domainEff, owner, name)
	if repoTok == "" {
		if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, owner, name); t != "" {
			repoTok = t
			svc.saveTokenRepo(ns, aliasEff, domainEff, owner, name, repoTok, false)
		}
	}
	token := domainTok
	if token == "" {
		if prompt != nil {
			// debug logs removed
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
			fmt.Printf("[GITHUB] AUTH cid=%s ns=%s alias=%s domain=%s owner=%s repo=%s wait=%s\n", cid, ns, aliasEff, domainEff, owner, name, wait)
			if wait > 0 && svc.waitForToken(ctx, ns, aliasEff, domainEff, owner, name, wait) {
				// After notify, prefer domain-level token
				token = svc.loadTokenPreferred(ns, aliasEff, domainEff, "", "")
				if token == "" {
					// Fallback to repo-level if only that was provided
					token = svc.loadTokenPreferred(ns, aliasEff, domainEff, owner, name)
				}
				// Only allow cross-namespace fallback when operating in the shared default namespace.
				if token == "" && ns == "default" {
					// Try domain-wide first across NS, then repo-level across NS
					token = svc.loadTokenPreferredAnyNS(aliasEff, domainEff, "", "")
					if token == "" {
						token = svc.loadTokenPreferredAnyNS(aliasEff, domainEff, owner, name)
					}
				}
				fmt.Printf("[GITHUB] AUTH cid=%s ns=%s alias=%s domain=%s owner=%s repo=%s got=%v\n", cid, ns, aliasEff, domainEff, owner, name, token != "")
			}
			// debug logs removed
		}
		if token == "" {
			return zero, fmt.Errorf("no token for alias=%s domain=%s; provide token via OOB or /github/auth/token", aliasEff, domainEff)
		}
	}
	// First try with domain-level token (retry on rate limiting)
	var out T
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		out, err = call(token)
		if err == nil {
			return out, nil
		}
		if errors.Is(err, adapter.ErrRateLimited) && sleepWithCtx(ctx, backoff(attempt)) {
			continue
		}
		break
	}
	// On insufficient access or bad creds with domain token, retry once with repo token if present
	if token == domainTok && repoTok != "" && repoTok != domainTok && (errors.Is(err, adapter.ErrUnauthorized) || errors.Is(err, adapter.ErrBadCredentials) || errors.Is(err, adapter.ErrForbidden) || errors.Is(err, adapter.ErrNotFound)) {
		for attempt := 0; attempt < 4; attempt++ {
			out, err = call(repoTok)
			if err == nil {
				return out, nil
			}
			if errors.Is(err, adapter.ErrRateLimited) && sleepWithCtx(ctx, backoff(attempt)) {
				continue
			}
			break
		}
	}
	if errors.Is(err, adapter.ErrUnauthorized) || errors.Is(err, adapter.ErrBadCredentials) {
		return zero, fmt.Errorf("unauthorized for alias=%s domain=%s owner=%s repo=%s; token invalid or insufficient scope", alias, domain, owner, name)
	}
	return zero, err
}
