package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"strings"

	afsscratchpad "github.com/viant/afs/scratchpad"
	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	sendgridauth "github.com/viant/mcp-toolbox/sendgrid/auth"
	sendgridsvc "github.com/viant/mcp-toolbox/sendgrid/service"
	nsprov "github.com/viant/mcp/server/namespace"
)

const IdentityNamespaceRequiredMessage = "Unauthorized: identity namespace is required"

//go:embed tools/sendgridSendMail.md
var sendgridSendMailDescription string

func registerTools(base *protoserver.DefaultHandler, handler *Handler) error {
	return protoserver.RegisterTool[*sendgridsvc.SendEmailInput, *sendgridsvc.SendEmailOutput](
		base.Registry,
		"sendgridSendMail",
		sendgridSendMailDescription,
		func(ctx context.Context, input *sendgridsvc.SendEmailInput) (*schema.CallToolResult, *jsonrpc.Error) {
			identity, err := resolveIdentity(ctx, handler.namespaceProvider)
			if err != nil {
				return nil, jsonrpc.NewError(schema.Unauthorized, IdentityNamespaceRequiredMessage, nil)
			}
			effectiveInput := cloneInput(input)
			if effectiveInput != nil && strings.TrimSpace(effectiveInput.From) == "" {
				from, err := resolveVerifiedEmail(ctx)
				if err != nil {
					return nil, jsonrpc.NewError(jsonrpc.InvalidParams, err.Error(), nil)
				}
				effectiveInput.From = from
			}
			ctx = afsscratchpad.ContextWithUserID(ctx, identity)
			output, err := handler.service.Send(ctx, effectiveInput)
			if err != nil {
				var validationErr *sendgridsvc.ValidationError
				if errors.As(err, &validationErr) {
					return nil, jsonrpc.NewError(jsonrpc.InvalidParams, validationErr.Error(), nil)
				}
				return toolErrorResult(err.Error()), nil
			}
			return successResult(output), nil
		},
	)
}

func cloneInput(input *sendgridsvc.SendEmailInput) *sendgridsvc.SendEmailInput {
	if input == nil {
		return nil
	}
	copy := *input
	return &copy
}

func resolveVerifiedEmail(ctx context.Context) (string, error) {
	claims, ok := sendgridauth.VerifiedClaimsFromContext(ctx)
	if !ok {
		return "", errors.New("verified caller email claim is required when from is omitted")
	}
	email, ok := claims["email"].(string)
	email = strings.TrimSpace(email)
	if !ok || email == "" {
		return "", errors.New("verified caller email claim is required when from is omitted")
	}
	return email, nil
}

func resolveIdentity(ctx context.Context, provider nsprov.Provider) (string, error) {
	if provider == nil {
		return "", errors.New(IdentityNamespaceRequiredMessage)
	}
	descriptor, err := provider.Namespace(ctx)
	if err != nil || descriptor.Kind != nsprov.KindIdentity || strings.TrimSpace(descriptor.Name) == "" {
		return "", errors.New(IdentityNamespaceRequiredMessage)
	}
	return strings.TrimSpace(descriptor.Name), nil
}

func successResult(output *sendgridsvc.SendEmailOutput) *schema.CallToolResult {
	data, _ := json.Marshal(output)
	structured := map[string]any{}
	_ = json.Unmarshal(data, &structured)
	return &schema.CallToolResult{
		Content:           []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(data)}},
		StructuredContent: structured,
	}
}

func toolErrorResult(message string) *schema.CallToolResult {
	isError := true
	return &schema.CallToolResult{
		IsError: &isError,
		Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: message}},
	}
}
