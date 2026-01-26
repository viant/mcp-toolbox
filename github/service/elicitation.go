package service

import (
	"context"
	"fmt"
	neturl "net/url"
	"strings"
	"time"

	oob "github.com/viant/mcp/server/oob"
)

// Namespace returns the effective authorization namespace for this request context,
// or "default" when not set.
func (s *Service) Namespace(ctx context.Context) string {
	if v := strings.TrimSpace(s.boundNamespace); v != "" {
		return v
	}
	if d, err := s.ns.Namespace(ctx); err == nil && d.Name != "" {
		return d.Name
	}
	return "default"
}

// WaitTimeout returns maximum time to wait for credentials; defaults to 300s if unset.
func (s *Service) WaitTimeout() time.Duration {
	if s.tunWait <= 0 {
		return 300 * time.Second
	}
	return s.tunWait
}

// ElicitCooldown returns cooldown between repeated elicitations; defaults to 60s if unset.
func (s *Service) ElicitCooldown() time.Duration {
	if s.tunCooldown <= 0 {
		return 60 * time.Second
	}
	return s.tunCooldown
}

func (s *Service) tokenWaitKey(ns, alias, domain string) string {
	return joinKey("wait", ns, alias, domain)
}

func lockAlias(alias string) string {
	a := strings.TrimSpace(alias)
	if a == "" {
		return "default"
	}
	if strings.Contains(a, "/") {
		return "default"
	}
	return a
}

// acquireCredLock provides a singleflight-style gate per (ns,alias,domain).
// Returns: leader flag, done channel (closed on success), and a release func(success) to cleanup.
func (s *Service) acquireCredLock(ns, alias, domain string) (bool, <-chan struct{}, func(success bool)) {
	alias = lockAlias(alias)
	key := s.tokenWaitKey(ns, alias, domain)
	s.credMu.Lock()
	if lk, ok := s.credLocks[key]; ok {
		ch := lk.done
		s.credMu.Unlock()
		return false, ch, func(bool) {}
	}
	lk := &credLock{done: make(chan struct{})}
	s.credLocks[key] = lk
	s.credMu.Unlock()
	release := func(success bool) {
		s.credMu.Lock()
		cur, ok := s.credLocks[key]
		if ok {
			delete(s.credLocks, key)
			if success {
				close(cur.done)
			}
		}
		s.credMu.Unlock()
	}
	return true, lk.done, release
}

// notifyToken wakes any goroutines waiting for a token for (alias,domain).
func (s *Service) notifyToken(ns, alias, domain string) {
	// Close by canonical gate key
	key := s.tokenWaitKey(ns, lockAlias(alias), domain)
	// Close singleflight lock if present
	s.credMu.Lock()
	if lk, ok := s.credLocks[key]; ok {
		delete(s.credLocks, key)
		close(lk.done)
	}
	s.credMu.Unlock()
}

// notifyTokenAll wakes any goroutines waiting for a token for (alias,domain) in any namespace.
func (s *Service) notifyTokenAll(alias, domain string) {
	alias = safePart(lockAlias(alias))
	domain = safePart(domain)
	s.credMu.Lock()
	woken := 0
	for key, lk := range s.credLocks {
		if lk == nil {
			continue
		}
		parts := strings.Split(key, "|")
		if len(parts) < 4 || parts[0] != safePart("wait") {
			continue
		}
		if parts[2] == alias && parts[3] == domain {
			delete(s.credLocks, key)
			close(lk.done)
			woken++
		}
	}
	s.credMu.Unlock()
	if woken > 0 {
		fmt.Printf("github auth: token waiters released alias=%q domain=%q count=%d\n", alias, domain, woken)
	}
}

// clearElicitedAll clears dedupe entries for any session for this alias/domain.
func (s *Service) clearElicitedAll(alias, domain string) {
	s.elicitMu.Lock()
	for k := range s.elicited {
		parts := strings.Split(k, "|")
		if len(parts) >= 4 {
			if parts[2] == safePart(alias) && parts[3] == safePart(domain) {
				delete(s.elicited, k)
			}
		}
	}
	for k := range s.elicitedGlobal {
		parts := strings.Split(k, "|")
		if len(parts) >= 4 {
			if parts[2] == safePart(alias) && parts[3] == safePart(domain) {
				delete(s.elicitedGlobal, k)
			}
		}
	}
	s.elicitMu.Unlock()
}

// maybeElicitOnce emits a single out-of-band prompt per (namespace,alias,domain) within a cooldown window.
func (s *Service) maybeElicitOnce(ctx context.Context, alias, domain, owner, name string, prompt func(string)) {
	if prompt == nil {
		fmt.Printf("github auth: elicit skipped (no prompt handler) alias=%q domain=%q owner=%q repo=%q\n", alias, domain, owner, name)
		return
	}
	// derive correlation id if needed
	// Minimal dedupe: per namespace+alias+domain within cooldown
	namespace := s.Namespace(ctx)
	domKey := s.normalizeDomain(domain)
	keySess := joinKey("elicit", namespace, alias, domKey)
	keyGlob := joinKey("elicitNS", namespace, alias, domKey)
	// Domain-scoped dedupe (suppresses extra prompts for same ns+domain across different aliases)
	keyDom := joinKey("elicitDomNS", namespace, domKey)
	now := time.Now()
	cooldown := s.ElicitCooldown()
	s.elicitMu.Lock()
	if t, ok := s.elicited[keySess]; ok && now.Sub(t) < cooldown {
		s.elicitMu.Unlock()
		return
	}
	if t, ok := s.elicitedGlobal[keyGlob]; ok && now.Sub(t) < cooldown {
		s.elicitMu.Unlock()
		return
	}
	if t, ok := s.elicitedGlobal[keyDom]; ok && now.Sub(t) < cooldown {
		s.elicitMu.Unlock()
		return
	}
	s.elicited[keySess] = now
	s.elicitedGlobal[keyGlob] = now
	s.elicitedGlobal[keyDom] = now
	s.elicitMu.Unlock()
	base := strings.TrimRight(s.baseURL, "/")
	q := neturl.Values{}
	q.Set("alias", alias)
	if domain != "" {
		q.Set("domain", domain)
	}
	if owner != "" && name != "" {
		q.Set("url", fmt.Sprintf("%s/%s/%s", domain, owner, name))
	}
	// If an OOB manager is available, create a pending entry to bind namespace and include uuid in URL.
	if s.oobMgr != nil {
		exp := time.Now().Add(s.WaitTimeout())
		id, cb, err := s.oobMgr.Create(ctx, oob.Spec[AuthOOBData]{
			Kind:      "github_oob",
			Alias:     alias,
			Resource:  domain,
			ExpiresAt: exp,
			Data:      AuthOOBData{Alias: alias, Domain: domain, Owner: owner, Repo: name},
		})
		if err == nil && id != "" {
			// Append non-sensitive query params for UX (alias/domain/url) to callback URL
			sep := "?"
			if strings.Contains(cb, "?") {
				sep = "&"
			}
			url := fmt.Sprintf("%s%s%s", cb, sep, q.Encode())
			fmt.Printf("github auth: elicit oob url=%q alias=%q domain=%q owner=%q repo=%q\n", url, alias, domain, owner, name)
			prompt(fmt.Sprintf("Open %s to provide credentials", url))
			return
		}
		if err != nil {
			fmt.Printf("github auth: elicit oob create failed alias=%q domain=%q owner=%q repo=%q err=%v\n", alias, domain, owner, name, err)
		}
	}
	// Fallback: plain OOB URL without uuid (less ideal; won’t bind namespace)
	url := fmt.Sprintf("%s/github/auth/oob?%s", base, q.Encode())
	fmt.Printf("github auth: elicit oob fallback url=%q alias=%q domain=%q owner=%q repo=%q\n", url, alias, domain, owner, name)
	prompt(fmt.Sprintf("Open %s to provide credentials", url))
}

// waitForToken checks for token existence, waiting up to timeout. Minimal shim returns immediately if present.
func (s *Service) waitForToken(ctx context.Context, ns, alias, domain, owner, name string, timeout time.Duration) bool {
	if t := s.loadTokenPreferred(ns, alias, domain, owner, name); t != "" {
		return true
	}
	_, done, release := s.acquireCredLock(ns, alias, domain)
	// If leader, do nothing special here (elicitation triggered upstream); just wait for done or timeout/cancel.
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	if timeout > 0 {
		fmt.Printf("github auth: waiting for token ns=%q alias=%q domain=%q owner=%q repo=%q timeout=%s\n", ns, alias, domain, owner, name, timeout)
	} else {
		fmt.Printf("github auth: waiting for token ns=%q alias=%q domain=%q owner=%q repo=%q\n", ns, alias, domain, owner, name)
	}
	select {
	case <-ctx.Done():
		// Cancel: release without success to allow future attempts
		release(false)
		fmt.Printf("github auth: token wait canceled ns=%q alias=%q domain=%q owner=%q repo=%q err=%v\n", ns, alias, domain, owner, name, ctx.Err())
		return false
	case <-timer.C:
		// Timeout: clean up gate without waking followers (they will also time out and re-attempt)
		release(false)
		has := s.loadTokenPreferred(ns, alias, domain, owner, name) != ""
		fmt.Printf("github auth: token wait timeout ns=%q alias=%q domain=%q owner=%q repo=%q found=%v\n", ns, alias, domain, owner, name, has)
		return has
	case <-done:
		fmt.Printf("github auth: token wait released ns=%q alias=%q domain=%q owner=%q repo=%q\n", ns, alias, domain, owner, name)
		return true
	}
}
