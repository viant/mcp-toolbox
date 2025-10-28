package mcp

import (
	"context"

	"github.com/viant/jsonrpc/transport"
	protoclient "github.com/viant/mcp-protocol/client"
	"github.com/viant/mcp-protocol/logger"
	protoserver "github.com/viant/mcp-protocol/server"
)

type Handler struct {
	*protoserver.DefaultHandler
	service *Service
	ops     protoclient.Operations
}

func NewHandler(service *Service) protoserver.NewHandler {
	return func(_ context.Context, notifier transport.Notifier, logger logger.Logger, clientOperation protoclient.Operations) (protoserver.Handler, error) {
		base := protoserver.NewDefaultHandler(notifier, logger, clientOperation)
		ret := &Handler{DefaultHandler: base, service: service, ops: clientOperation}
		if err := registerTools(base, ret); err != nil {
			return nil, err
		}
		return ret, nil
	}
}
