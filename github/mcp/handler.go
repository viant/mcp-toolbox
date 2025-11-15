package mcp

import (
	"context"
	"sync"

	"github.com/viant/jsonrpc/transport"
	protoclient "github.com/viant/mcp-protocol/client"
	"github.com/viant/mcp-protocol/logger"
	protoserver "github.com/viant/mcp-protocol/server"
	ghservice "github.com/viant/mcp-toolbox/github/service"
	nsprov "github.com/viant/mcp/server/namespace"
)

type Handler struct {
	*protoserver.DefaultHandler
	service *ghservice.Service
	ops     protoclient.Operations

	// Namespace provider used to resolve the caller namespace from context.
	// This aligns with mcp/server/namespace README and enables per-namespace services.
	nsProvider *nsprov.DefaultProvider

	// Optional fields to support per-namespace service resolution in subsequent steps.
	// When factory is nil, the handler returns the base service for all calls (backward compatible).
	svcFactory func(namespace string) (*ghservice.Service, error)
	svcByNS    map[string]*ghservice.Service
	svcMu      sync.RWMutex
}

func NewHandler(service *ghservice.Service) protoserver.NewHandler {
	return func(_ context.Context, notifier transport.Notifier, logger logger.Logger, clientOperation protoclient.Operations) (protoserver.Handler, error) {
		base := protoserver.NewDefaultHandler(notifier, logger, clientOperation)
		// Initialize a default namespace provider. Prefer identity and fall back to token-hash,
		// matching other services in this repository.
		provider := nsprov.NewProvider(&nsprov.Config{PreferIdentity: true, Hash: nsprov.HashConfig{Algorithm: "md5", Prefix: "tkn-"}, Path: nsprov.PathConfig{Prefix: "id-", Sanitize: true, MaxLen: 120}})
		ret := &Handler{
			DefaultHandler: base,
			service:        service,
			ops:            clientOperation,
			nsProvider:     provider,
			svcByNS:        map[string]*ghservice.Service{},
			// Factory that binds the base service to the resolved namespace.
			svcFactory: func(ns string) (*ghservice.Service, error) {
				return service.Bound(ns), nil
			},
		}
		if err := registerTools(base, ret); err != nil {
			return nil, err
		}
		return ret, nil
	}
}

// resolveService resolves the effective namespace from context and returns a namespace-bound service instance.
// For now, if no factory is configured, it returns the base service to remain backward compatible.
// In later steps, this will be used by tool handlers to route calls per namespace.
func (h *Handler) resolveService(ctx context.Context) (context.Context, *ghservice.Service, error) {
	if h == nil {
		return ctx, nil, nil
	}
	// Derive namespace descriptor and inject into context for downstream consumers.
	desc, _ := h.nsProvider.Namespace(ctx)
	if desc.Name == "" {
		desc.Name = "default"
	}
	ctxWithNS := nsprov.IntoContext(ctx, desc)
	// Per-namespace service via factory with caching.
	ns := desc.Name
	h.svcMu.RLock()
	svc := h.svcByNS[ns]
	h.svcMu.RUnlock()
	if svc != nil {
		return ctxWithNS, svc, nil
	}
	// Create and cache
	h.svcMu.Lock()
	defer h.svcMu.Unlock()
	if v := h.svcByNS[ns]; v != nil {
		return ctxWithNS, v, nil
	}
	created, err := h.svcFactory(ns)
	if err != nil {
		return ctxWithNS, nil, err
	}
	h.svcByNS[ns] = created
	return ctxWithNS, created, nil
}
