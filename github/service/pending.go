package service

import "sync"

type PendingAuth struct {
    UUID      string
    Alias     string
    Namespace string
    UserCode  string
    VerifyURL string
}

type PendingAuths struct {
    mu   sync.RWMutex
    byID map[string]*PendingAuth
    byNS map[string]map[string]*PendingAuth
}

func NewPendingAuths() *PendingAuths { return &PendingAuths{byID: map[string]*PendingAuth{}, byNS: map[string]map[string]*PendingAuth{}} }
func (p *PendingAuths) Put(x *PendingAuth) { p.mu.Lock(); defer p.mu.Unlock(); p.byID[x.UUID] = x; if x.Namespace==""{x.Namespace="default"}; if p.byNS[x.Namespace]==nil{p.byNS[x.Namespace]=map[string]*PendingAuth{} }; p.byNS[x.Namespace][x.UUID]=x }
func (p *PendingAuths) Get(uuid string) (*PendingAuth, bool) { p.mu.RLock(); defer p.mu.RUnlock(); x, ok := p.byID[uuid]; return x, ok }
func (p *PendingAuths) Remove(uuid string) { p.mu.Lock(); defer p.mu.Unlock(); x, ok := p.byID[uuid]; if ok { delete(p.byID, uuid) }; if ok && x != nil { if m, ok2 := p.byNS[x.Namespace]; ok2 { delete(m, uuid); if len(m)==0 { delete(p.byNS, x.Namespace) } } } }
func (p *PendingAuths) ListNamespace(ns string) []*PendingAuth { p.mu.RLock(); defer p.mu.RUnlock(); out := []*PendingAuth{}; for _, v := range p.byNS[ns] { out = append(out, v) }; return out }
func (p *PendingAuths) ClearNamespace(ns string) []string { p.mu.Lock(); defer p.mu.Unlock(); ids := []string{}; if m, ok := p.byNS[ns]; ok { for id := range m { delete(p.byID, id); ids = append(ids, id) }; delete(p.byNS, ns) }; return ids }
