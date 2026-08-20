package mcp

import (
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
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

func TestResolveVerifiedEmail(t *testing.T) {
	ctx := sendgridauth.ContextWithVerifiedClaims(context.Background(), map[string]any{
		"email": "  alice@example.com  ",
		"sub":   "alice-subject",
	})
	email, err := resolveVerifiedEmail(ctx)
	if err != nil {
		t.Fatalf("resolveVerifiedEmail failed: %v", err)
	}
	if email != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com", email)
	}

	for _, ctx := range []context.Context{
		context.Background(),
		sendgridauth.ContextWithVerifiedClaims(context.Background(), map[string]any{"sub": "alice-subject"}),
	} {
		if _, err := resolveVerifiedEmail(ctx); err == nil {
			t.Fatal("expected missing verified email failure")
		}
	}
}

func TestResolveCallerEnvelopeAddsCurrentUserAndExplicitRecipients(t *testing.T) {
	ctx := sendgridauth.ContextWithVerifiedClaims(context.Background(), map[string]any{
		"email": "  alice@example.com  ",
		"sub":   "alice-subject",
	})
	input := &sendgridsvc.SendEmailInput{
		To:            []string{"john.example@gmail.com", "JOHN.EXAMPLE@gmail.com", "ALICE@example.com"},
		ToCurrentUser: true,
	}

	if err := resolveCallerEnvelope(ctx, input); err != nil {
		t.Fatalf("resolveCallerEnvelope failed: %v", err)
	}
	if input.From != "alice@example.com" {
		t.Fatalf("From = %q, want alice@example.com", input.From)
	}
	if input.ToCurrentUser {
		t.Fatal("ToCurrentUser must be consumed before service validation")
	}
	wantTo := []string{"john.example@gmail.com", "ALICE@example.com"}
	if !reflect.DeepEqual(input.To, wantTo) {
		t.Fatalf("To = %#v, want %#v", input.To, wantTo)
	}
}

func TestResolveCallerEnvelopeAppendsCurrentUser(t *testing.T) {
	ctx := sendgridauth.ContextWithVerifiedClaims(context.Background(), map[string]any{
		"email": "alice@example.com",
	})
	input := &sendgridsvc.SendEmailInput{
		From:          "verified-sender@example.com",
		To:            []string{"john.example@gmail.com"},
		ToCurrentUser: true,
	}

	if err := resolveCallerEnvelope(ctx, input); err != nil {
		t.Fatalf("resolveCallerEnvelope failed: %v", err)
	}
	wantTo := []string{"john.example@gmail.com", "alice@example.com"}
	if !reflect.DeepEqual(input.To, wantTo) {
		t.Fatalf("To = %#v, want %#v", input.To, wantTo)
	}
	if input.From != "verified-sender@example.com" {
		t.Fatalf("From = %q, want explicit sender", input.From)
	}
}

func TestResolveCallerEnvelopeFailsAtomicallyWithoutVerifiedEmail(t *testing.T) {
	input := &sendgridsvc.SendEmailInput{
		From:          "verified-sender@example.com",
		To:            []string{"john.example@gmail.com"},
		ToCurrentUser: true,
	}
	want := cloneInput(input)

	err := resolveCallerEnvelope(context.Background(), input)
	if err == nil || !strings.Contains(err.Error(), "toCurrentUser is true") {
		t.Fatalf("resolveCallerEnvelope error = %v", err)
	}
	if !reflect.DeepEqual(input, want) {
		t.Fatalf("failed resolution mutated input: got %#v, want %#v", input, want)
	}
}

func TestSendGridToolFailsBeforeSendWhenCurrentUserEmailIsMissing(t *testing.T) {
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
		namespaceProvider: identityProvider([]string{"sub"}),
	}
	if err := registerTools(base, handler); err != nil {
		t.Fatalf("registerTools failed: %v", err)
	}
	ctx := sendgridauth.ContextWithVerifiedClaims(context.Background(), map[string]any{
		"sub": "alice-subject",
	})

	result, rpcErr := handler.CallTool(ctx, &jsonrpc.TypedRequest[*schema.CallToolRequest]{
		Request: &schema.CallToolRequest{Params: schema.CallToolRequestParams{
			Name: "sendgridSendMail",
			Arguments: map[string]any{
				"from":          "verified-sender@example.com",
				"to":            []any{"john.example@gmail.com"},
				"toCurrentUser": true,
				"subject":       "Test",
				"bodyText":      "Body",
			},
		}},
	})
	if result != nil {
		t.Fatalf("unexpected tool result: %#v", result)
	}
	if rpcErr == nil || rpcErr.Code != jsonrpc.InvalidParams || !strings.Contains(rpcErr.Message, "toCurrentUser is true") {
		t.Fatalf("unexpected RPC error: %#v", rpcErr)
	}
}

func TestSendEmailInputAllowsServerResolvedRecipientWithoutTo(t *testing.T) {
	data, err := json.Marshal(&sendgridsvc.SendEmailInput{ToCurrentUser: true})
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	if decoded["toCurrentUser"] != true {
		t.Fatalf("missing toCurrentUser in public input: %s", data)
	}
	if _, ok := decoded["to"]; ok {
		t.Fatalf("empty to must be omittable for current-user resolution: %s", data)
	}
}

func TestSendGridToolSchemaAllowsServerResolvedRecipient(t *testing.T) {
	base := protoserver.NewDefaultHandler(nil, nil, nil)
	if err := registerTools(base, &Handler{DefaultHandler: base}); err != nil {
		t.Fatalf("registerTools failed: %v", err)
	}
	tools := base.ListRegisteredTools()
	if len(tools) != 1 || tools[0].Name != "sendgridSendMail" {
		t.Fatalf("unexpected registered tools: %#v", tools)
	}
	tool := tools[0]
	if _, ok := tool.InputSchema.Properties["toCurrentUser"]; !ok {
		t.Fatalf("toCurrentUser is missing from the public input schema: %#v", tool.InputSchema.Properties)
	}
	if _, ok := tool.InputSchema.Properties["to"]; !ok {
		t.Fatalf("to is missing from the public input schema: %#v", tool.InputSchema.Properties)
	}
	for _, required := range tool.InputSchema.Required {
		if required == "to" || required == "toCurrentUser" {
			t.Fatalf("recipient alternatives must remain optional in JSON Schema; required = %#v", tool.InputSchema.Required)
		}
	}
}

func TestCloneInputKeepsCallerInputUnchanged(t *testing.T) {
	original := &sendgridsvc.SendEmailInput{
		From: "",
		To:   make([]string, 1, 2),
		Attachments: []sendgridsvc.EmailAttachment{{
			Name: "report.pdf",
		}},
	}
	original.To[0] = "alice@example.com"
	copy := cloneInput(original)
	copy.From = "sender@example.com"
	copy.To[0] = "bob@example.com"
	copy.To = append(copy.To, "carol@example.com")
	copy.Attachments[0].Name = "changed.pdf"
	if original.From != "" {
		t.Fatalf("clone modified caller input: %#v", original)
	}
	if original.To[0] != "alice@example.com" || len(original.To) != 1 {
		t.Fatalf("clone shared recipient backing storage: %#v", original.To)
	}
	if original.Attachments[0].Name != "report.pdf" {
		t.Fatalf("clone shared attachment backing storage: %#v", original.Attachments)
	}
}

func TestCloneInputAllowsNilValidation(t *testing.T) {
	if cloneInput(nil) != nil {
		t.Fatal("nil input must remain nil so the service can return its validation error")
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
		Status:       "accepted",
		Provider:     "sendgrid",
		StatusCode:   202,
		MessageID:    "provider-id",
		ResolvedFrom: "sender@example.com",
		ResolvedTo:   []string{"alice@example.com", "bob@example.com"},
	}
	result := successResult(output)
	if result.StructuredContent["status"] != "accepted" ||
		result.StructuredContent["provider"] != "sendgrid" ||
		result.StructuredContent["statusCode"] != float64(202) ||
		result.StructuredContent["messageId"] != "provider-id" ||
		result.StructuredContent["resolvedFrom"] != "sender@example.com" {
		t.Fatalf("unexpected structured content: %#v", result.StructuredContent)
	}
	if !reflect.DeepEqual(result.StructuredContent["resolvedTo"], []any{"alice@example.com", "bob@example.com"}) {
		t.Fatalf("unexpected resolved recipients: %#v", result.StructuredContent["resolvedTo"])
	}
	if _, wrapped := result.StructuredContent["result"]; wrapped {
		t.Fatalf("structured content is unexpectedly wrapped: %#v", result.StructuredContent)
	}
	var textOutput sendgridsvc.SendEmailOutput
	text := result.Content[0].(schema.TextContent).Text
	if err := json.Unmarshal([]byte(text), &textOutput); err != nil || !reflect.DeepEqual(textOutput, *output) {
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
