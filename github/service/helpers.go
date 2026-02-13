package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/viant/mcp-toolbox/github/adapter"
)

func logCredReuse(ctx context.Context, ns, alias, domain, owner, repo, scope, source string) {
	log.Printf("github auth: reuse credentials ns=%q alias=%q domain=%q owner=%q repo=%q scope=%s source=%s cid=%q", ns, alias, domain, owner, repo, scope, source, CID(ctx))
}

func logCredPrompt(ctx context.Context, ns, alias, domain, owner, repo, reason string) {
	log.Printf("github auth: prompt for credentials ns=%q alias=%q domain=%q owner=%q repo=%q reason=%s cid=%q", ns, alias, domain, owner, repo, reason, CID(ctx))
}

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
	domainEff := svc.normalizeDomain(domain)
	if domainEff == "" {
		domainEff = "github.com"
	}

	token := svc.loadToken(ns, aliasEff, domainEff)
	tokenSrc := ""
	if token != "" {
		tokenSrc = "memory"
	}
	if token == "" {
		if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, "", ""); t != "" {
			token = t
			tokenSrc = "secrets"
			// hydrate memory for future calls
			svc.saveToken(ns, aliasEff, domainEff, token)
		}
	}
	if token != "" {
		logCredReuse(ctx, ns, aliasEff, domainEff, "", "", "domain", tokenSrc)
	}
	if token == "" {
		// For public github.com, attempt unauthenticated call first; only elicit on permission errors.
		if svc.normalizeDomain(domainEff) == "github.com" {
			var out T
			var err error
			for attempt := 0; attempt < 4; attempt++ {
				out, err = call("")
				if err == nil {
					return out, nil
				}
				if errors.Is(err, adapter.ErrRateLimited) && sleepWithCtx(ctx, backoff(attempt)) {
					continue
				}
				break
			}
			if !(errors.Is(err, adapter.ErrUnauthorized) || errors.Is(err, adapter.ErrBadCredentials) || errors.Is(err, adapter.ErrForbidden) || errors.Is(err, adapter.ErrSSORequired)) {
				return zero, err
			}
		}
		if prompt != nil {
			// Elicit once and wait briefly for token to arrive
			logCredPrompt(ctx, ns, aliasEff, domainEff, "", "", "missing_token")
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
				tokenSrc = "memory"
				if token == "" {
					if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, "", ""); t != "" {
						token = t
						tokenSrc = "secrets"
					}
				}
				if token != "" {
					logCredReuse(ctx, ns, aliasEff, domainEff, "", "", "domain", tokenSrc)
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
		if prompt != nil {
			logCredPrompt(ctx, ns, aliasEff, domainEff, "", "", "unauthorized")
			svc.maybeElicitOnce(ctx, aliasEff, domainEff, "", "", prompt)
			wait := svc.WaitTimeout()
			if dl, ok := ctx.Deadline(); ok {
				if d := time.Until(dl) - 500*time.Millisecond; d > 0 && d < wait {
					wait = d
				} else if d <= 0 {
					wait = 0
				}
			}
			if wait > 0 && svc.waitForToken(ctx, ns, aliasEff, domainEff, "", "", wait) {
				newToken := svc.loadToken(ns, aliasEff, domainEff)
				newSrc := "memory"
				if newToken == "" {
					if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, "", ""); t != "" {
						newToken = t
						newSrc = "secrets"
					}
				}
				if newToken != "" && newToken != token {
					logCredReuse(ctx, ns, aliasEff, domainEff, "", "", "domain", newSrc)
					for attempt := 0; attempt < 4; attempt++ {
						out, err = call(newToken)
						if err == nil {
							return out, nil
						}
						if errors.Is(err, adapter.ErrRateLimited) && sleepWithCtx(ctx, backoff(attempt)) {
							continue
						}
						break
					}
				}
			}
		}
		return zero, fmt.Errorf("unauthorized for alias=%s domain=%s; token invalid or insufficient scope", alias, domain)
	}
	return zero, err
}

// withRepoCredentialRetry tries domain-level credentials first; on unauthorized, falls back to repo-level.
func withRepoCredentialRetry[T any](ctx context.Context, svc *Service, alias, domain, owner, name string, prompt func(string), call func(token string) (T, error)) (T, error) {
	var zero T
	ns := svc.Namespace(ctx)
	// Normalize alias/domain to align waiter and notifier keys
	aliasEff := svc.normalizeAlias(alias)
	if aliasEff == "" {
		aliasEff = "default"
	}
	domainEff := svc.normalizeDomain(domain)
	if domainEff == "" {
		domainEff = "github.com"
	}

	// debug logs removed
	// Load domain-level first (including canonical alias fallback), then repo-level
	domainTok := svc.loadTokenPreferred(ns, aliasEff, domainEff, "", "")
	domainSrc := ""
	if domainTok != "" {
		domainSrc = "memory"
	}
	if domainTok == "" {
		if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, "", ""); t != "" {
			domainTok = t
			domainSrc = "secrets"
			svc.saveTokenDomain(ns, aliasEff, domainEff, domainTok, false)
		}
	}
	repoTok := svc.loadTokenPreferred(ns, aliasEff, domainEff, owner, name)
	repoSrc := ""
	if repoTok != "" {
		repoSrc = "memory"
	}
	if repoTok == "" {
		if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, owner, name); t != "" {
			repoTok = t
			repoSrc = "secrets"
			svc.saveTokenRepo(ns, aliasEff, domainEff, owner, name, repoTok, false)
		}
	}
	// Prefer least-privileged repo token when available.
	token := repoTok
	if token == "" {
		token = domainTok
	}
	if token != "" {
		if token == repoTok {
			logCredReuse(ctx, ns, aliasEff, domainEff, owner, name, "repo", repoSrc)
		} else {
			logCredReuse(ctx, ns, aliasEff, domainEff, owner, name, "domain", domainSrc)
		}
	}
	if token == "" {
		// For public github.com, try unauthenticated call first; only elicit on permission errors.
		if svc.normalizeDomain(domainEff) == "github.com" {
			var out T
			var err error
			for attempt := 0; attempt < 4; attempt++ {
				out, err = call("")
				if err == nil {
					return out, nil
				}
				if errors.Is(err, adapter.ErrRateLimited) && sleepWithCtx(ctx, backoff(attempt)) {
					continue
				}
				break
			}
			if !(errors.Is(err, adapter.ErrUnauthorized) || errors.Is(err, adapter.ErrBadCredentials) || errors.Is(err, adapter.ErrForbidden) || errors.Is(err, adapter.ErrSSORequired) || errors.Is(err, adapter.ErrNotFound)) {
				return zero, err
			}
		}
		if prompt != nil {
			logCredPrompt(ctx, ns, aliasEff, domainEff, owner, name, "missing_token")
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
			// debug logs removed
			if wait > 0 && svc.waitForToken(ctx, ns, aliasEff, domainEff, owner, name, wait) {
				// After notify, prefer repo-level token for least privilege.
				tokenScope := "repo"
				token = svc.loadTokenPreferred(ns, aliasEff, domainEff, owner, name)
				tokenSrc := "memory"
				if token == "" {
					if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, owner, name); t != "" {
						token = t
						tokenSrc = "secrets"
					}
				}
				if token == "" {
					// Fallback to domain-level if only that was provided
					tokenScope = "domain"
					token = svc.loadTokenPreferred(ns, aliasEff, domainEff, "", "")
					if token != "" {
						tokenSrc = "memory"
					}
					if token == "" {
						if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, "", ""); t != "" {
							token = t
							tokenSrc = "secrets"
						}
					}
				}
				if token != "" {
					logCredReuse(ctx, ns, aliasEff, domainEff, owner, name, tokenScope, tokenSrc)
				}
			}
			// debug logs removed
		}
		// If no token found, attempt alias inference after OOB to align with user-provided alias.
		if token == "" {
			if inf, _ := svc.inferAlias(ctx, domainEff, owner, name); inf != "" && inf != aliasEff {
				token = svc.loadTokenPreferred(ns, inf, domainEff, owner, name)
				if token == "" {
					token = svc.loadTokenPreferred(ns, inf, domainEff, "", "")
				}
			}
		}
		if token == "" {
			return zero, fmt.Errorf("no token for alias=%s domain=%s; provide token via OOB or /github/auth/token", aliasEff, domainEff)
		}
	}
	// First try with repo-level token when present (retry on rate limiting).
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
	// On insufficient access or bad creds with repo token, retry with domain token if present.
	if token == repoTok && domainTok != "" && domainTok != repoTok && (errors.Is(err, adapter.ErrUnauthorized) || errors.Is(err, adapter.ErrBadCredentials) || errors.Is(err, adapter.ErrForbidden) || errors.Is(err, adapter.ErrNotFound)) {
		logCredReuse(ctx, ns, aliasEff, domainEff, owner, name, "domain", domainSrc)
		for attempt := 0; attempt < 4; attempt++ {
			out, err = call(domainTok)
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
		if prompt != nil {
			logCredPrompt(ctx, ns, aliasEff, domainEff, owner, name, "unauthorized")
			svc.maybeElicitOnce(ctx, aliasEff, domainEff, owner, name, prompt)
			wait := svc.WaitTimeout()
			if dl, ok := ctx.Deadline(); ok {
				if d := time.Until(dl) - 500*time.Millisecond; d > 0 && d < wait {
					wait = d
				} else if d <= 0 {
					wait = 0
				}
			}
			if wait > 0 && svc.waitForToken(ctx, ns, aliasEff, domainEff, owner, name, wait) {
				newScope := "repo"
				newToken := svc.loadTokenPreferred(ns, aliasEff, domainEff, owner, name)
				newSrc := "memory"
				if newToken == "" {
					if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, owner, name); t != "" {
						newToken = t
						newSrc = "secrets"
					}
				}
				if newToken == "" {
					newScope = "domain"
					newToken = svc.loadTokenPreferred(ns, aliasEff, domainEff, "", "")
					if newToken != "" {
						newSrc = "memory"
					}
					if newToken == "" {
						if t := svc.loadTokenFromSecrets(ctx, ns, aliasEff, domainEff, "", ""); t != "" {
							newToken = t
							newSrc = "secrets"
						}
					}
				}
				if newToken != "" && newToken != token {
					logCredReuse(ctx, ns, aliasEff, domainEff, owner, name, newScope, newSrc)
					for attempt := 0; attempt < 4; attempt++ {
						out, err = call(newToken)
						if err == nil {
							return out, nil
						}
						if errors.Is(err, adapter.ErrRateLimited) && sleepWithCtx(ctx, backoff(attempt)) {
							continue
						}
						break
					}
				}
			}
		}
		return zero, fmt.Errorf("unauthorized for alias=%s domain=%s owner=%s repo=%s; token invalid or insufficient scope", alias, domain, owner, name)
	}
	return zero, err
}
