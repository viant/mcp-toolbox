package mcp

import (
	"context"

	"github.com/viant/jsonrpc/transport"
	protoclient "github.com/viant/mcp-protocol/client"
	"github.com/viant/mcp-protocol/logger"
	protoserver "github.com/viant/mcp-protocol/server"
	browsersvc "github.com/viant/mcp-toolbox/browser/service"
)

type Handler struct {
	*protoserver.DefaultHandler
	service         *browsersvc.Service
	ops             protoclient.Operations
	legacyToolNames bool
}

type HandlerOptions struct {
	LegacyToolNames bool
}

func NewHandler(service *browsersvc.Service) protoserver.NewHandler {
	return NewHandlerWithOptions(service, HandlerOptions{LegacyToolNames: true})
}

func NewHandlerWithOptions(service *browsersvc.Service, options HandlerOptions) protoserver.NewHandler {
	return func(_ context.Context, notifier transport.Notifier, logger logger.Logger, clientOperation protoclient.Operations) (protoserver.Handler, error) {
		base := protoserver.NewDefaultHandler(notifier, logger, clientOperation)
		ret := &Handler{DefaultHandler: base, service: service, ops: clientOperation, legacyToolNames: options.LegacyToolNames}
		if err := registerTools(base, ret); err != nil {
			return nil, err
		}
		return ret, nil
	}
}
