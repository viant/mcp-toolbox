package mcp

import (
	"context"
	"testing"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	"github.com/viant/mcp-toolbox/outlook/graph"
)

func TestAllOutlookToolsRequireIdentityBeforeGraphOrPending(t *testing.T) {
	svc := NewService(&Config{SecretsBase: t.TempDir()})
	base := protoserver.NewDefaultHandler(nil, nil, nil)
	handler := &Handler{DefaultHandler: base, service: svc}
	if err := registerTools(base, handler); err != nil {
		t.Fatalf("registerTools failed: %v", err)
	}

	toolNames := []string{
		"outlookListMail",
		"outlookSendMail",
		"outlookListEvents",
		"outlookCreateEvent",
		"outlookListTasks",
		"outlookCreateTask",
	}
	for _, name := range toolNames {
		t.Run(name, func(t *testing.T) {
			_, rpcErr := handler.CallTool(context.Background(), &jsonrpc.TypedRequest[*schema.CallToolRequest]{
				Request: &schema.CallToolRequest{Params: schema.CallToolRequestParams{
					Name: name,
				}},
			})
			if rpcErr == nil {
				t.Fatal("expected unauthorized error")
			}
			if rpcErr.Code != schema.Unauthorized {
				t.Fatalf("unexpected error code: got %d want %d (%v)", rpcErr.Code, schema.Unauthorized, rpcErr)
			}
			if rpcErr.Message != graph.IdentityNamespaceRequiredMessage {
				t.Fatalf("unexpected error message: %q", rpcErr.Message)
			}
		})
	}

	svc.pending.mu.RLock()
	pendingCount := len(svc.pending.byID)
	svc.pending.mu.RUnlock()
	if pendingCount != 0 {
		t.Fatalf("identity failures created %d pending auth sessions", pendingCount)
	}
}
