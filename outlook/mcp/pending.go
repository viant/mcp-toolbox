package mcp

import (
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type PendingAuth struct {
	UUID      string
	Alias     string
	TenantID  string
	ElicitID  string
	Namespace string
	done      chan struct{}
	Message   *azidentity.DeviceCodeMessage
}

type PendingAuths struct {
	mu   sync.RWMutex
	byID map[string]*PendingAuth
	byNS map[string]map[string]*PendingAuth // ns -> uuid -> pending
}

func NewPendingAuths() *PendingAuths {
	return &PendingAuths{byID: make(map[string]*PendingAuth), byNS: make(map[string]map[string]*PendingAuth)}
}

func (p *PendingAuths) Put(x *PendingAuth) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byID[x.UUID] = x
	if x.Namespace == "" {
		x.Namespace = "default"
	}
	m, ok := p.byNS[x.Namespace]
	if !ok {
		m = map[string]*PendingAuth{}
		p.byNS[x.Namespace] = m
	}
	m[x.UUID] = x
}

func (p *PendingAuths) Get(uuid string) (*PendingAuth, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	x, ok := p.byID[uuid]
	return x, ok
}

func (p *PendingAuths) Complete(uuid string) {
	p.mu.Lock()
	x, ok := p.byID[uuid]
	if ok {
		delete(p.byID, uuid)
	}
	if ok && x != nil {
		if m, ok2 := p.byNS[x.Namespace]; ok2 {
			delete(m, uuid)
			if len(m) == 0 {
				delete(p.byNS, x.Namespace)
			}
		}
	}
	p.mu.Unlock()
	if ok {
		select {
		case x.done <- struct{}{}:
		default:
		}
		close(x.done)
	}
}

func (p *PendingAuths) Cancel(uuid string) {
	p.Complete(uuid)
}

// ListNamespace returns a snapshot of pending auths for a namespace.
func (p *PendingAuths) ListNamespace(ns string) []*PendingAuth {
	p.mu.RLock()
	defer p.mu.RUnlock()
	m := p.byNS[ns]
	out := make([]*PendingAuth, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// ClearNamespace removes all pending auths for a namespace and returns cleared UUIDs.
func (p *PendingAuths) ClearNamespace(ns string) []string {
	p.mu.Lock()
	ids := make([]string, 0)
	if m, ok := p.byNS[ns]; ok {
		for id, x := range m {
			delete(p.byID, id)
			ids = append(ids, id)
			// signal completion/cancel
			if x != nil {
				select {
				case x.done <- struct{}{}:
				default:
				}
				close(x.done)
			}
		}
		delete(p.byNS, ns)
	}
	p.mu.Unlock()
	return ids
}
