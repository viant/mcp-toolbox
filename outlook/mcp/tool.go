package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"

	"github.com/viant/mcp-toolbox/outlook/graph"
)

//go:embed tools/outlookListMail.md
var outlookListMailDesc string

//go:embed tools/outlookSendMail.md
var outlookSendMailDesc string

//go:embed tools/outlookListEvents.md
var outlookListEventsDesc string

//go:embed tools/outlookCreateEvent.md
var outlookCreateEventDesc string

//go:embed tools/outlookListTasks.md
var outlookListTasksDesc string

//go:embed tools/outlookCreateTask.md
var outlookCreateTaskDesc string

func registerTools(base *protoserver.DefaultHandler, h *Handler) error {
	svc := h.service
	ops := h.ops

	userPrompt := func(ctx context.Context, m azidentity.DeviceCodeMessage) error {
		if ops != nil && ops.Implements(schema.MethodElicitationCreate) {
			text := fmt.Sprintf("Open %s and enter code: %s", m.VerificationURL, m.UserCode)
			elicitID := newUUID()
			_, _ = ops.Elicit(ctx, &jsonrpc.TypedRequest[*schema.ElicitRequest]{Request: &schema.ElicitRequest{
				Params: schema.ElicitRequestParams{ElicitationId: elicitID, Message: text, Mode: string(schema.ElicitRequestParamsModeUrl), Url: m.VerificationURL},
			}})
		}
		return nil
	}

	var msgPrompt func(ctx context.Context) func(msg string)
	msgPrompt = func(ctx context.Context) func(msg string) {
		return func(msg string) {
			deviceCodeMessage := azidentity.DeviceCodeMessage{
				UserCode:        extractCode(msg),
				VerificationURL: extractURL(msg),
				Message:         msg,
			}
			_ = userPrompt(ctx, deviceCodeMessage)
		}
	}

	mailSvc := graph.NewMailService(svc.GraphManager())
	calSvc := graph.NewCalendarService(svc.GraphManager())
	taskSvc := graph.NewTaskService(svc.GraphManager())

	// List mail
	if err := protoserver.RegisterTool[*graph.ListMailInput, *graph.ListMailOutput](base.Registry, "outlookListMail", outlookListMailDesc, func(ctx context.Context, in *graph.ListMailInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in.Account.Alias == "" {
			return buildErrorResult("account.alias is required")
		}
		if in.Account.TenantID == "" {
			in.Account.TenantID = svc.TenantID()
		}
		out, err := mailSvc.List(ctx, in, graph.DefaultScopes(), msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Send mail
	if err := protoserver.RegisterTool[*graph.SendEmailInput, *struct{}](base.Registry, "outlookSendMail", outlookSendMailDesc, func(ctx context.Context, in *graph.SendEmailInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in.Account.Alias == "" {
			return buildErrorResult("account.alias is required")
		}
		if in.Account.TenantID == "" {
			in.Account.TenantID = svc.TenantID()
		}
		if err := mailSvc.Send(ctx, in, graph.DefaultScopes(), msgPrompt(ctx)); err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, map[string]any{"status": "sent"})
	}); err != nil {
		return err
	}

	// List events
	if err := protoserver.RegisterTool[*graph.ListEventsInput, *graph.ListEventsOutput](base.Registry, "outlookListEvents", outlookListEventsDesc, func(ctx context.Context, in *graph.ListEventsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in.Account.Alias == "" {
			return buildErrorResult("account.alias is required")
		}
		if in.Account.TenantID == "" {
			in.Account.TenantID = svc.TenantID()
		}
		out, err := calSvc.List(ctx, in, graph.DefaultScopes(), msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Create event
	if err := protoserver.RegisterTool[*graph.CreateEventInput, *graph.CalendarEvent](base.Registry, "outlookCreateEvent", outlookCreateEventDesc, func(ctx context.Context, in *graph.CreateEventInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in.Account.Alias == "" {
			return buildErrorResult("account.alias is required")
		}
		if in.Account.TenantID == "" {
			in.Account.TenantID = svc.TenantID()
		}
		out, err := calSvc.Create(ctx, in, graph.DefaultScopes(), msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// List tasks
	if err := protoserver.RegisterTool[*graph.ListTasksInput, *graph.ListTasksOutput](base.Registry, "outlookListTasks", outlookListTasksDesc, func(ctx context.Context, in *graph.ListTasksInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in.Account.Alias == "" {
			return buildErrorResult("account.alias is required")
		}
		if in.Account.TenantID == "" {
			in.Account.TenantID = svc.TenantID()
		}
		out, err := taskSvc.List(ctx, in, graph.DefaultScopes(), msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Create task
	if err := protoserver.RegisterTool[*graph.CreateTaskInput, *graph.Task](base.Registry, "outlookCreateTask", outlookCreateTaskDesc, func(ctx context.Context, in *graph.CreateTaskInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if in.Account.Alias == "" {
			return buildErrorResult("account.alias is required")
		}
		if in.Account.TenantID == "" {
			in.Account.TenantID = svc.TenantID()
		}
		out, err := taskSvc.Create(ctx, in, graph.DefaultScopes(), msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	return nil
}

// ensureAuthorized removed; device userPrompt is handled inline via elicitation.

// Helpers
func buildErrorResult(message string) (*schema.CallToolResult, *jsonrpc.Error) {
	return nil, jsonrpc.NewError(jsonrpc.InvalidParams, message, nil)
}

func buildSuccessResult(service *Service, payload any) (*schema.CallToolResult, *jsonrpc.Error) {
	if service.UseTextField() {
		b, _ := json.Marshal(payload)
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{{Type: "text", Text: string(b)}}}, nil
	}
	return &schema.CallToolResult{StructuredContent: map[string]any{"result": payload}}, nil
}

func newUUID() string { return uuid.New().String() }

func buildToolErrorResult(service *Service, message string) *schema.CallToolResult {
	isErr := true
	if service.UseTextField() {
		return &schema.CallToolResult{IsError: &isErr, Content: []schema.CallToolResultContentElem{{Type: "text", Text: message}}}
	}
	return &schema.CallToolResult{IsError: &isErr, StructuredContent: map[string]any{"error": message}}
}

// local-only helper retained for device prompt parsing

// Minimal helpers to extract device login URL/code from Azure prompt message.
func extractURL(msg string) string {
	if m := regexp.MustCompile(`https?://[^\s]+`).FindString(msg); m != "" {
		return m
	}
	return "https://microsoft.com/devicelogin"
}
func extractCode(msg string) string {
	if m := regexp.MustCompile(`(?i)code\s+([A-Z0-9-]+)`).FindStringSubmatch(msg); len(m) == 2 {
		return m[1]
	}
	return ""
}
