package mcp

import (
	"context"

	"github.com/viant/jsonrpc/transport"
	protoclient "github.com/viant/mcp-protocol/client"
	"github.com/viant/mcp-protocol/logger"
	protoserver "github.com/viant/mcp-protocol/server"
	sendgridsvc "github.com/viant/mcp-toolbox/sendgrid/service"
	nsprov "github.com/viant/mcp/server/namespace"
)

type Handler struct {
	*protoserver.DefaultHandler
	service           *sendgridsvc.Service
	namespaceProvider nsprov.Provider
}

// NewHandler creates the independent SendGrid MCP handler.
func NewHandler(service *sendgridsvc.Service, cfg *Config) protoserver.NewHandler {
	if cfg == nil {
		cfg = &Config{}
	}
	claimKeys := NormalizeNamespaceClaimKeys(cfg.NamespaceClaimKeys)
	provider := cfg.NamespaceProvider
	if provider == nil {
		provider = NewVerifiedIdentityProvider(claimKeys)
	}
	return func(_ context.Context, notifier transport.Notifier, logger logger.Logger, clientOperation protoclient.Operations) (protoserver.Handler, error) {
		base := protoserver.NewDefaultHandler(notifier, logger, clientOperation)
		result := &Handler{
			DefaultHandler:    base,
			service:           service,
			namespaceProvider: provider,
		}
		if err := registerTools(base, result); err != nil {
			return nil, err
		}
		return result, nil
	}
}
