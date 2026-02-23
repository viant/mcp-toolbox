package mcp

import (
	"context"
	_ "embed"
	"encoding/json"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	"github.com/viant/mcp-toolbox/iplookup/service"
)

//go:embed tools/lookup.md
var descLookup string

// RegisterTools registers iplookup tools in the provided handler.
func RegisterTools(base *protoserver.DefaultHandler, svc *service.Service) error {
	if err := protoserver.RegisterTool[[]service.Query, []service.Result](base.Registry, "iplookup_lookup", descLookup, func(ctx context.Context, in []service.Query) (*schema.CallToolResult, *jsonrpc.Error) {
		out := svc.Lookup(ctx, in)
		b, _ := json.Marshal(out)
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(b)}}}, nil
	}); err != nil {
		return err
	}
	return nil
}
