package mcp

import (
	"context"

	"github.com/viant/jsonrpc/transport"
	protoclient "github.com/viant/mcp-protocol/client"
	"github.com/viant/mcp-protocol/logger"
	protoserver "github.com/viant/mcp-protocol/server"
	"github.com/viant/mcp-toolbox/iplookup/service"
)

type Handler struct {
	*protoserver.DefaultHandler
	service *service.Service
}

func NewHandler(service *service.Service) protoserver.NewHandler {
	return func(_ context.Context, notifier transport.Notifier, logger logger.Logger, clientOperation protoclient.Operations) (protoserver.Handler, error) {
		base := protoserver.NewDefaultHandler(notifier, logger, clientOperation)
		ret := &Handler{DefaultHandler: base, service: service}
		if err := RegisterTools(base, service); err != nil {
			return nil, err
		}
		return ret, nil
	}
}
