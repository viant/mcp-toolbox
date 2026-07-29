package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/authorization"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	sendgridauth "github.com/viant/mcp-toolbox/sendgrid/auth"
	sendgridsvc "github.com/viant/mcp-toolbox/sendgrid/service"
	nsprov "github.com/viant/mcp/server/namespace"
	"github.com/viant/scy"
)

func testAPIKeyRef(t *testing.T) scy.EncodedResource {
	t.Helper()
	target := "file://" + filepath.ToSlash(filepath.Join(t.TempDir(), "sendgrid-api-key.enc"))
	if err := scy.New().Store(context.Background(), scy.NewSecret(
		"SG.test-key",
		scy.NewResource(nil, target, "blowfish://default"),
	)); err != nil {
		t.Fatalf("encrypt test API key: %v", err)
	}
	return scy.EncodedResource(target + "|blowfish://default")
}

func TestSendGridToolRequiresIdentityBeforeValidationOrProvider(t *testing.T) {
	service, err := sendgridsvc.NewService(context.Background(), sendgridsvc.Config{
		APIKeyRef:          testAPIKeyRef(t),
		MaxConcurrentSends: 1,
		SendTimeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	base := protoserver.NewDefaultHandler(nil, nil, nil)
	provider := identityProvider([]string{"email", "sub"})
	handler := &Handler{DefaultHandler: base, service: service, namespaceProvider: provider}
	if err := registerTools(base, handler); err != nil {
		t.Fatalf("registerTools failed: %v", err)
	}

	_, rpcErr := handler.CallTool(context.Background(), &jsonrpc.TypedRequest[*schema.CallToolRequest]{
		Request: &schema.CallToolRequest{Params: schema.CallToolRequestParams{
			Name:      "sendgridSendMail",
			Arguments: map[string]any{"from": "invalid"},
		}},
	})
	if rpcErr == nil || rpcErr.Code != schema.Unauthorized || rpcErr.Message != IdentityNamespaceRequiredMessage {
		t.Fatalf("unexpected RPC error: %#v", rpcErr)
	}
}

func TestResolveIdentityUsesConfiguredClaimOrder(t *testing.T) {
	ctx := sendgridauth.ContextWithVerifiedClaims(context.Background(), map[string]any{
		"email": "alice@example.com",
		"sub":   "alice-subject",
	})
	identity, err := resolveIdentity(ctx, identityProvider([]string{"sub", "email"}))
	if err != nil {
		t.Fatalf("resolveIdentity failed: %v", err)
	}
	if identity != "alice-subject" {
		t.Fatalf("identity = %q, want alice-subject", identity)
	}

	for _, invalid := range []context.Context{
		context.Background(),
		contextWithBearer(context.Background(), "forged.jwt.token"),
		sendgridauth.ContextWithVerifiedClaims(context.Background(), map[string]any{"aud": "sendgrid"}),
	} {
		if _, err := resolveIdentity(invalid, identityProvider(nil)); err == nil {
			t.Fatal("expected strict identity failure")
		}
	}
}

func TestSendGridToolReturnsValidationErrorForAuthenticatedCaller(t *testing.T) {
	service, err := sendgridsvc.NewService(context.Background(), sendgridsvc.Config{
		APIKeyRef: testAPIKeyRef(t),
	})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	base := protoserver.NewDefaultHandler(nil, nil, nil)
	handler := &Handler{
		DefaultHandler:    base,
		service:           service,
		namespaceProvider: identityProvider(nil),
	}
	if err := registerTools(base, handler); err != nil {
		t.Fatalf("registerTools failed: %v", err)
	}
	ctx := sendgridauth.ContextWithVerifiedClaims(context.Background(), map[string]any{"email": "alice@example.com"})

	_, rpcErr := handler.CallTool(ctx, &jsonrpc.TypedRequest[*schema.CallToolRequest]{
		Request: &schema.CallToolRequest{Params: schema.CallToolRequestParams{
			Name: "sendgridSendMail",
			Arguments: map[string]any{
				"from":     "invalid",
				"to":       []any{"bob@example.com"},
				"subject":  "Test",
				"bodyText": "Body",
			},
		}},
	})
	if rpcErr == nil || rpcErr.Code != jsonrpc.InvalidParams {
		t.Fatalf("unexpected RPC error: %#v", rpcErr)
	}
}

func TestSuccessResultMatchesAdvertisedOutputSchema(t *testing.T) {
	output := &sendgridsvc.SendEmailOutput{
		Status:     "accepted",
		Provider:   "sendgrid",
		StatusCode: 202,
		MessageID:  "provider-id",
	}
	result := successResult(output)
	if result.StructuredContent["status"] != "accepted" ||
		result.StructuredContent["provider"] != "sendgrid" ||
		result.StructuredContent["statusCode"] != float64(202) ||
		result.StructuredContent["messageId"] != "provider-id" {
		t.Fatalf("unexpected structured content: %#v", result.StructuredContent)
	}
	if _, wrapped := result.StructuredContent["result"]; wrapped {
		t.Fatalf("structured content is unexpectedly wrapped: %#v", result.StructuredContent)
	}
	var textOutput sendgridsvc.SendEmailOutput
	text := result.Content[0].(schema.TextContent).Text
	if err := json.Unmarshal([]byte(text), &textOutput); err != nil || textOutput != *output {
		t.Fatalf("unexpected text output %q: %v", text, err)
	}
}

func TestToolErrorResultDoesNotViolateSuccessOutputSchema(t *testing.T) {
	result := toolErrorResult("provider rejected request")
	if result.IsError == nil || !*result.IsError {
		t.Fatalf("tool error is not marked as an error: %#v", result)
	}
	if result.StructuredContent != nil {
		t.Fatalf("tool error advertised nonconforming structured content: %#v", result.StructuredContent)
	}
	text, ok := result.Content[0].(schema.TextContent)
	if !ok || text.Text != "provider rejected request" {
		t.Fatalf("unexpected tool error content: %#v", result.Content)
	}
}

func identityProvider(claimKeys []string) nsprov.Provider {
	return NewVerifiedIdentityProvider(claimKeys)
}

func contextWithBearer(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authorization.TokenKey, &authorization.Token{Token: "Bearer " + token})
}
