package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

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

	ensureAuthorized := func(ctx context.Context, alias, tenant string) error {
		start := time.Now()
		scopes := svc.GraphScopes()
		check := svc.GraphManager().AuthCheck(ctx, alias, tenant, scopes)
		debugf("ensureAuthorized alias=%q tenant=%q auth_status=%q reason=%q err=%v deadline_in=%s check_elapsed=%s", alias, tenant, check.Status, check.Reason, check.Err, debugDeadline(ctx), time.Since(start).Round(time.Millisecond))
		switch check.Status {
		case graph.AuthCheckReady:
			return nil
		case graph.AuthCheckTransient:
			return fmt.Errorf("%s", graph.UserMessageForAuthError(check.Err))
		case graph.AuthCheckFailed:
			message := graph.UserMessageForAuthError(check.Err)
			if message == "" {
				message = "Outlook authentication check failed"
			}
			return fmt.Errorf("%s", message)
		case graph.AuthCheckNeedsInteractive:
			// continue below
		default:
			return fmt.Errorf("Outlook authentication check returned unexpected status %q", check.Status)
		}
		session := svc.startAuthSession(ctx, alias, tenant, scopes)
		if session == nil {
			debugf("ensureAuthorized alias=%q tenant=%q startAuthSession=nil elapsed=%s", alias, tenant, time.Since(start).Round(time.Millisecond))
			return fmt.Errorf("Outlook sign-in session could not be started")
		}
		debugf("ensureAuthorized alias=%q tenant=%q session=%q status=%q elapsed=%s", alias, tenant, session.UUID, session.Status, time.Since(start).Round(time.Millisecond))
		if session.Status == AuthStatusAuthenticated {
			return nil
		}
		url := svc.authSessionURL(session)
		if ops == nil || !ops.Implements(schema.MethodElicitationCreate) {
			debugf("ensureAuthorized alias=%q tenant=%q session=%q no_elicitation url=%q elapsed=%s", alias, tenant, session.UUID, url, time.Since(start).Round(time.Millisecond))
			return fmt.Errorf("Outlook sign-in required: %s", url)
		}
		elicitStart := time.Now()
		if _, err := ops.Elicit(ctx, &jsonrpc.TypedRequest[*schema.ElicitRequest]{Request: &schema.ElicitRequest{
			Params: schema.ElicitRequestParams{ElicitationId: newUUID(), Message: "Sign in to Outlook", Mode: schema.ElicitRequestParamsModeUrl, Url: url},
		}}); err != nil {
			debugf("ensureAuthorized alias=%q tenant=%q session=%q elicit_error=%v elapsed=%s total=%s", alias, tenant, session.UUID, err, time.Since(elicitStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond))
			return fmt.Errorf("Outlook sign-in prompt failed: %w", err)
		}
		debugf("ensureAuthorized alias=%q tenant=%q session=%q elicit_ok elapsed=%s waiting deadline_in=%s", alias, tenant, session.UUID, time.Since(elicitStart).Round(time.Millisecond), debugDeadline(ctx))
		waitStart := time.Now()
		err := svc.waitForAuthSession(ctx, session)
		debugf("ensureAuthorized alias=%q tenant=%q session=%q wait_done err=%v wait_elapsed=%s total=%s deadline_in=%s", alias, tenant, session.UUID, err, time.Since(waitStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
		return err
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
		if err := ensureAuthorized(ctx, in.Account.Alias, in.Account.TenantID); err != nil {
			return buildErrorResult(err.Error())
		}
		out, err := mailSvc.List(ctx, in, svc.GraphScopes(), nil)
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Send mail
	if err := protoserver.RegisterTool[*graph.SendEmailInput, *struct{}](base.Registry, "outlookSendMail", outlookSendMailDesc, func(ctx context.Context, in *graph.SendEmailInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := time.Now()
		debugf("outlookSendMail start alias=%q tenant=%q to_count=%d attachment_count=%d deadline_in=%s", in.Account.Alias, in.Account.TenantID, len(in.To), len(in.Attachments), debugDeadline(ctx))
		if in.Account.Alias == "" {
			return buildErrorResult("account.alias is required")
		}
		if in.Account.TenantID == "" {
			in.Account.TenantID = svc.TenantID()
		}
		authStart := time.Now()
		if err := ensureAuthorized(ctx, in.Account.Alias, in.Account.TenantID); err != nil {
			debugf("outlookSendMail auth_failed err=%v auth_elapsed=%s total=%s deadline_in=%s", err, time.Since(authStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
			return buildErrorResult(err.Error())
		}
		debugf("outlookSendMail auth_ok auth_elapsed=%s scratchpad_user=%q deadline_in=%s", time.Since(authStart).Round(time.Millisecond), svc.scratchpadUserIDFromContext(ctx), debugDeadline(ctx))
		ctx = svc.withScratchpadUser(ctx)
		sendStart := time.Now()
		if err := mailSvc.Send(ctx, in, svc.GraphScopes(), nil); err != nil {
			debugf("outlookSendMail send_failed err=%v send_elapsed=%s total=%s deadline_in=%s", err, time.Since(sendStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
			return buildErrorResult(err.Error())
		}
		debugf("outlookSendMail sent send_elapsed=%s total=%s deadline_in=%s", time.Since(sendStart).Round(time.Millisecond), time.Since(start).Round(time.Millisecond), debugDeadline(ctx))
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
		if err := ensureAuthorized(ctx, in.Account.Alias, in.Account.TenantID); err != nil {
			return buildErrorResult(err.Error())
		}
		out, err := calSvc.List(ctx, in, svc.GraphScopes(), nil)
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
		if err := ensureAuthorized(ctx, in.Account.Alias, in.Account.TenantID); err != nil {
			return buildErrorResult(err.Error())
		}
		out, err := calSvc.Create(ctx, in, svc.GraphScopes(), nil)
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
		if err := ensureAuthorized(ctx, in.Account.Alias, in.Account.TenantID); err != nil {
			return buildErrorResult(err.Error())
		}
		out, err := taskSvc.List(ctx, in, svc.GraphScopes(), nil)
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
		if err := ensureAuthorized(ctx, in.Account.Alias, in.Account.TenantID); err != nil {
			return buildErrorResult(err.Error())
		}
		out, err := taskSvc.Create(ctx, in, svc.GraphScopes(), nil)
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
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(b)}}}, nil
	}
	return &schema.CallToolResult{StructuredContent: map[string]any{"result": payload}}, nil
}

func newUUID() string { return uuid.New().String() }

func buildToolErrorResult(service *Service, message string) *schema.CallToolResult {
	isErr := true
	if service.UseTextField() {
		return &schema.CallToolResult{IsError: &isErr, Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: message}}}
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
