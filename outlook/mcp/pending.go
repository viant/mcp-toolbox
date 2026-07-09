package mcp

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type AuthStatus string

const (
	AuthStatusWaitingForCode AuthStatus = "waiting_for_code"
	AuthStatusWaitingForUser AuthStatus = "waiting_for_user"
	AuthStatusAuthenticated  AuthStatus = "authenticated"
	AuthStatusFailed         AuthStatus = "failed"
	AuthStatusExpired        AuthStatus = "expired"
	AuthStatusCanceled       AuthStatus = "canceled"
)

type PendingAuth struct {
	UUID         string
	Alias        string
	TenantID     string
	ElicitID     string
	Namespace    string
	Scopes       []string
	Key          string
	Flow         string
	State        string
	CodeVerifier string
	AuthURL      string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	Status       AuthStatus
	Message      string
	done         chan struct{}
	doneClosed   bool
	Error        string
}

func (p *PendingAuth) active(now time.Time) bool {
	if p == nil {
		return false
	}
	switch p.Status {
	case AuthStatusAuthenticated, AuthStatusFailed, AuthStatusExpired, AuthStatusCanceled:
		return false
	}
	return p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt)
}

func (p *PendingAuth) Done() <-chan struct{} {
	if p == nil || p.done == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return p.done
}

type PendingAuths struct {
	mu      sync.RWMutex
	byID    map[string]*PendingAuth
	byNS    map[string]map[string]*PendingAuth // ns -> uuid -> pending
	byKey   map[string]*PendingAuth
	byState map[string]*PendingAuth
}

func NewPendingAuths() *PendingAuths {
	return &PendingAuths{
		byID:    make(map[string]*PendingAuth),
		byNS:    make(map[string]map[string]*PendingAuth),
		byKey:   make(map[string]*PendingAuth),
		byState: make(map[string]*PendingAuth),
	}
}

func authSessionKey(ns, alias, tenantID string, scopes []string) string {
	ns = strings.TrimSpace(ns)
	if ns == "" {
		ns = "default"
	}
	alias = strings.TrimSpace(alias)
	tenantID = strings.TrimSpace(tenantID)
	normScopes := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope != "" {
			normScopes = append(normScopes, scope)
		}
	}
	sort.Strings(normScopes)
	return ns + "|" + alias + "|" + tenantID + "|" + strings.Join(normScopes, ",")
}

func (p *PendingAuths) Put(x *PendingAuth) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if x.CreatedAt.IsZero() {
		x.CreatedAt = time.Now()
	}
	if x.Status == "" {
		x.Status = AuthStatusWaitingForCode
	}
	p.byID[x.UUID] = x
	if x.Namespace == "" {
		x.Namespace = "default"
	}
	if x.Key == "" {
		x.Key = authSessionKey(x.Namespace, x.Alias, x.TenantID, x.Scopes)
	}
	if x.done == nil {
		x.done = make(chan struct{}, 1)
	}
	m, ok := p.byNS[x.Namespace]
	if !ok {
		m = map[string]*PendingAuth{}
		p.byNS[x.Namespace] = m
	}
	m[x.UUID] = x
	p.byKey[x.Key] = x
	if x.State != "" {
		p.byState[x.State] = x
	}
}

func (p *PendingAuths) GetOrCreate(ns, alias, tenantID string, scopes []string, ttl time.Duration, newID func() string) (*PendingAuth, bool) {
	now := time.Now()
	key := authSessionKey(ns, alias, tenantID, scopes)
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.byKey[key]; existing != nil {
		if existing.active(now) {
			return clonePendingAuth(existing), false
		}
		p.removeLocked(existing, true)
	}
	if ns == "" {
		ns = "default"
	}
	id := newID()
	session := &PendingAuth{
		UUID:      id,
		Alias:     alias,
		TenantID:  tenantID,
		Namespace: ns,
		Scopes:    append([]string(nil), scopes...),
		Key:       key,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		Status:    AuthStatusWaitingForCode,
		done:      make(chan struct{}, 1),
	}
	p.byID[id] = session
	if p.byNS[ns] == nil {
		p.byNS[ns] = map[string]*PendingAuth{}
	}
	p.byNS[ns][id] = session
	p.byKey[key] = session
	return clonePendingAuth(session), true
}

func (p *PendingAuths) GetOrCreateAuthCode(ns, alias, tenantID string, scopes []string, ttl time.Duration, newID func() string, state, verifier, authURL string) (*PendingAuth, bool) {
	now := time.Now()
	key := authSessionKey(ns, alias, tenantID, scopes)
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.byKey[key]; existing != nil {
		if existing.active(now) {
			if existing.AuthURL == "" {
				existing.Flow = "auth-code"
				existing.State = state
				existing.CodeVerifier = verifier
				existing.AuthURL = authURL
				existing.Status = AuthStatusWaitingForUser
				if state != "" {
					p.byState[state] = existing
				}
			}
			return clonePendingAuth(existing), false
		}
		p.removeLocked(existing, true)
	}
	if ns == "" {
		ns = "default"
	}
	id := newID()
	session := &PendingAuth{
		UUID:         id,
		Alias:        alias,
		TenantID:     tenantID,
		Namespace:    ns,
		Scopes:       append([]string(nil), scopes...),
		Key:          key,
		Flow:         "auth-code",
		State:        state,
		CodeVerifier: verifier,
		AuthURL:      authURL,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		Status:       AuthStatusWaitingForUser,
		done:         make(chan struct{}, 1),
	}
	p.byID[id] = session
	if p.byNS[ns] == nil {
		p.byNS[ns] = map[string]*PendingAuth{}
	}
	p.byNS[ns][id] = session
	p.byKey[key] = session
	if state != "" {
		p.byState[state] = session
	}
	return clonePendingAuth(session), true
}

func (p *PendingAuths) SetOAuthStart(uuid, state, verifier, authURL string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x := p.byID[uuid]
	if x == nil {
		return
	}
	if x.State != "" && x.State != state {
		delete(p.byState, x.State)
	}
	x.Flow = "auth-code"
	x.State = state
	x.CodeVerifier = verifier
	x.AuthURL = authURL
	x.Status = AuthStatusWaitingForUser
	if state != "" {
		p.byState[state] = x
	}
}

func (p *PendingAuths) GetByState(state string) (*PendingAuth, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x := p.byState[state]
	if x == nil {
		return nil, false
	}
	if !x.ExpiresAt.IsZero() && time.Now().After(x.ExpiresAt) {
		switch x.Status {
		case AuthStatusAuthenticated, AuthStatusFailed, AuthStatusExpired, AuthStatusCanceled:
		default:
			x.Status = AuthStatusExpired
			p.signalLocked(x)
		}
		return clonePendingAuth(x), false
	}
	return clonePendingAuth(x), true
}

func (p *PendingAuths) ClearState(state string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.byState, state)
}

func (p *PendingAuths) SetMessage(uuid, message string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if x := p.byID[uuid]; x != nil {
		x.Message = message
		if x.Status == AuthStatusWaitingForCode {
			x.Status = AuthStatusWaitingForUser
		}
	}
}

func (p *PendingAuths) Complete(uuid string) {
	p.finish(uuid, AuthStatusAuthenticated, "")
}

func (p *PendingAuths) Fail(uuid, message string) {
	p.finish(uuid, AuthStatusFailed, message)
}

func (p *PendingAuths) Expire(uuid string) {
	p.finish(uuid, AuthStatusExpired, "")
}

func (p *PendingAuths) Cancel(uuid string) {
	p.finish(uuid, AuthStatusCanceled, "")
}

func (p *PendingAuths) finish(uuid string, status AuthStatus, message string) {
	p.mu.Lock()
	x := p.byID[uuid]
	if x != nil {
		x.Status = status
		if message != "" {
			x.Error = message
		}
		p.signalLocked(x)
	}
	p.mu.Unlock()
}

func (p *PendingAuths) Get(uuid string) (*PendingAuth, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	x, ok := p.byID[uuid]
	if !ok {
		return nil, false
	}
	if !x.ExpiresAt.IsZero() && time.Now().After(x.ExpiresAt) {
		switch x.Status {
		case AuthStatusAuthenticated, AuthStatusFailed, AuthStatusExpired, AuthStatusCanceled:
		default:
			x.Status = AuthStatusExpired
			p.signalLocked(x)
		}
	}
	return clonePendingAuth(x), true
}

// ListNamespace returns a snapshot of pending auths for a namespace.
func (p *PendingAuths) ListNamespace(ns string) []*PendingAuth {
	p.mu.RLock()
	defer p.mu.RUnlock()
	m := p.byNS[ns]
	out := make([]*PendingAuth, 0, len(m))
	for _, v := range m {
		out = append(out, clonePendingAuth(v))
	}
	return out
}

// ClearNamespace removes all pending auths for a namespace and returns cleared UUIDs.
func (p *PendingAuths) ClearNamespace(ns string) []string {
	p.mu.Lock()
	ids := make([]string, 0)
	if m, ok := p.byNS[ns]; ok {
		for id, x := range m {
			ids = append(ids, id)
			p.removeLocked(x, true)
		}
	}
	p.mu.Unlock()
	return ids
}

// ClearAlias removes all pending auths for an alias in a namespace and returns cleared UUIDs.
func (p *PendingAuths) ClearAlias(ns, alias string) []string {
	p.mu.Lock()
	ids := make([]string, 0)
	if m, ok := p.byNS[ns]; ok {
		for id, x := range m {
			if x == nil || x.Alias != alias {
				continue
			}
			ids = append(ids, id)
			p.removeLocked(x, true)
		}
	}
	p.mu.Unlock()
	return ids
}

func (p *PendingAuths) removeLocked(x *PendingAuth, canceled bool) {
	if x == nil {
		return
	}
	if canceled {
		x.Status = AuthStatusCanceled
	}
	delete(p.byID, x.UUID)
	delete(p.byKey, x.Key)
	if x.State != "" {
		delete(p.byState, x.State)
	}
	if m := p.byNS[x.Namespace]; m != nil {
		delete(m, x.UUID)
		if len(m) == 0 {
			delete(p.byNS, x.Namespace)
		}
	}
	p.signalLocked(x)
}

func (p *PendingAuths) signalLocked(x *PendingAuth) {
	if x == nil || x.done == nil || x.doneClosed {
		return
	}
	close(x.done)
	x.doneClosed = true
}

func clonePendingAuth(x *PendingAuth) *PendingAuth {
	if x == nil {
		return nil
	}
	cp := *x
	cp.Scopes = append([]string(nil), x.Scopes...)
	return &cp
}
