package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	jirasvc "github.com/viant/mcp-toolbox/jira/service"
)

// Tool descriptions
//
//go:embed tools/jiraListProjects.md
var descListProjects string

//go:embed tools/jiraSearchIssues.md
var descSearchIssues string

//go:embed tools/jiraCreateIssue.md
var descCreateIssue string

//go:embed tools/jiraAddComment.md
var descAddComment string

//go:embed tools/jiraListComments.md
var descListComments string

//go:embed tools/jiraCreateMeta.md
var descCreateMeta string

//go:embed tools/jiraListCustomFieldContexts.md
var descListCustomFieldContexts string

//go:embed tools/jiraListCustomFieldOptions.md
var descListCustomFieldOptions string

//go:embed tools/jiraListUsers.md
var descListUsers string

//go:embed tools/jiraGetIssue.md
var descGetIssue string

//go:embed tools/jiraUpdateIssue.md
var descUpdateIssue string

//go:embed tools/jiraTransitionIssue.md
var descTransitionIssue string

//go:embed tools/jiraAddWatcher.md
var descAddWatcher string

//go:embed tools/jiraRemoveWatcher.md
var descRemoveWatcher string

//go:embed tools/jiraListWorklogs.md
var descListWorklogs string

//go:embed tools/jiraAddWorklog.md
var descAddWorklog string

//go:embed tools/jiraBulkCreateIssues.md
var descBulkCreateIssues string

//go:embed tools/jiraBulkUpdateIssues.md
var descBulkUpdateIssues string

//go:embed tools/jiraDeleteIssue.md
var descDeleteIssue string

func registerTools(base *protoserver.DefaultHandler, h *Handler) error {
	svc := h.service
	ops := h.ops

	// Non-blocking elicitation helper: open Jira OOB page to paste PAT when creds missing.
	prompt := func(ctx context.Context, alias, domain string) {
		if ops == nil || !ops.Implements(schema.MethodElicitationCreate) {
			return
		}
		text := fmt.Sprintf("Authorize Jira access for %s/%s", domain, alias)
		url := fmt.Sprintf("%s/jira/auth/oob?alias=%s&domain=%s", strings.TrimRight(svc.CallbackBaseURL(), "/"), urlQuery(alias), urlQuery(domain))
		go func() {
			ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = ops.Elicit(ctx2, &jsonrpc.TypedRequest[*schema.ElicitRequest]{Request: &schema.ElicitRequest{Params: schema.ElicitRequestParams{ElicitationId: newUUID(), Message: text, Mode: schema.ElicitRequestParamsModeUrl, Url: url}}})
		}()
	}

	// List projects
	if err := protoserver.RegisterTool[*jirasvc.ListProjectsInput, *jirasvc.ListProjectsOutput](base.Registry, "jiraListProjects", descListProjects, func(ctx context.Context, in *jirasvc.ListProjectsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ListProjects(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			// Fire OOB and give user a moment to paste PAT
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			// Brief backoff then retry once
			time.Sleep(2 * time.Second)
			out, err = svc.ListProjects(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Search issues
	if err := protoserver.RegisterTool[*jirasvc.SearchIssuesInput, *jirasvc.SearchIssuesOutput](base.Registry, "jiraSearchIssues", descSearchIssues, func(ctx context.Context, in *jirasvc.SearchIssuesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if strings.TrimSpace(in.JQL) == "" {
			return buildErrorResult("jql is required")
		}
		out, err := svc.SearchIssues(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.SearchIssues(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Create issue
	if err := protoserver.RegisterTool[*jirasvc.CreateIssueInput, *jirasvc.CreateIssueOutput](base.Registry, "jiraCreateIssue", descCreateIssue, func(ctx context.Context, in *jirasvc.CreateIssueInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CreateIssue(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.CreateIssue(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Add comment
	if err := protoserver.RegisterTool[*jirasvc.AddCommentInput, *jirasvc.AddCommentOutput](base.Registry, "jiraAddComment", descAddComment, func(ctx context.Context, in *jirasvc.AddCommentInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.AddComment(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.AddComment(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// List comments
	if err := protoserver.RegisterTool[*jirasvc.ListCommentsInput, *jirasvc.ListCommentsOutput](base.Registry, "jiraListComments", descListComments, func(ctx context.Context, in *jirasvc.ListCommentsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ListComments(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.ListComments(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Create meta
	if err := protoserver.RegisterTool[*jirasvc.CreateMetaInput, *jirasvc.CreateMetaOutput](base.Registry, "jiraCreateMeta", descCreateMeta, func(ctx context.Context, in *jirasvc.CreateMetaInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.CreateMeta(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.CreateMeta(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Custom field contexts
	if err := protoserver.RegisterTool[*jirasvc.ListCustomFieldContextsInput, *jirasvc.ListCustomFieldContextsOutput](base.Registry, "jiraListCustomFieldContexts", descListCustomFieldContexts, func(ctx context.Context, in *jirasvc.ListCustomFieldContextsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ListCustomFieldContexts(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.ListCustomFieldContexts(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Custom field options
	if err := protoserver.RegisterTool[*jirasvc.ListCustomFieldOptionsInput, *jirasvc.ListCustomFieldOptionsOutput](base.Registry, "jiraListCustomFieldOptions", descListCustomFieldOptions, func(ctx context.Context, in *jirasvc.ListCustomFieldOptionsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ListCustomFieldOptions(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.ListCustomFieldOptions(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// List users
	if err := protoserver.RegisterTool[*jirasvc.ListUsersInput, *jirasvc.ListUsersOutput](base.Registry, "jiraListUsers", descListUsers, func(ctx context.Context, in *jirasvc.ListUsersInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ListUsers(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.ListUsers(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Get issue
	if err := protoserver.RegisterTool[*jirasvc.GetIssueInput, *jirasvc.GetIssueOutput](base.Registry, "jiraGetIssue", descGetIssue, func(ctx context.Context, in *jirasvc.GetIssueInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.GetIssue(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.GetIssue(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Update issue
	if err := protoserver.RegisterTool[*jirasvc.UpdateIssueInput, *jirasvc.UpdateIssueOutput](base.Registry, "jiraUpdateIssue", descUpdateIssue, func(ctx context.Context, in *jirasvc.UpdateIssueInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.UpdateIssue(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.UpdateIssue(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Transition issue
	if err := protoserver.RegisterTool[*jirasvc.TransitionIssueInput, *jirasvc.TransitionIssueOutput](base.Registry, "jiraTransitionIssue", descTransitionIssue, func(ctx context.Context, in *jirasvc.TransitionIssueInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.TransitionIssue(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.TransitionIssue(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Add watcher
	if err := protoserver.RegisterTool[*jirasvc.AddWatcherInput, *jirasvc.AddWatcherOutput](base.Registry, "jiraAddWatcher", descAddWatcher, func(ctx context.Context, in *jirasvc.AddWatcherInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.AddWatcher(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.AddWatcher(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Remove watcher
	if err := protoserver.RegisterTool[*jirasvc.RemoveWatcherInput, *jirasvc.RemoveWatcherOutput](base.Registry, "jiraRemoveWatcher", descRemoveWatcher, func(ctx context.Context, in *jirasvc.RemoveWatcherInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.RemoveWatcher(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.RemoveWatcher(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// List worklogs
	if err := protoserver.RegisterTool[*jirasvc.ListWorklogsInput, *jirasvc.ListWorklogsOutput](base.Registry, "jiraListWorklogs", descListWorklogs, func(ctx context.Context, in *jirasvc.ListWorklogsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ListWorklogs(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.ListWorklogs(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Add worklog
	if err := protoserver.RegisterTool[*jirasvc.AddWorklogInput, *jirasvc.AddWorklogOutput](base.Registry, "jiraAddWorklog", descAddWorklog, func(ctx context.Context, in *jirasvc.AddWorklogInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.AddWorklog(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.AddWorklog(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Bulk create issues
	if err := protoserver.RegisterTool[*jirasvc.BulkCreateIssuesInput, *jirasvc.BulkCreateIssuesOutput](base.Registry, "jiraBulkCreateIssues", descBulkCreateIssues, func(ctx context.Context, in *jirasvc.BulkCreateIssuesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.BulkCreateIssues(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.BulkCreateIssues(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Bulk update issues
	if err := protoserver.RegisterTool[*jirasvc.BulkUpdateIssuesInput, *jirasvc.BulkUpdateIssuesOutput](base.Registry, "jiraBulkUpdateIssues", descBulkUpdateIssues, func(ctx context.Context, in *jirasvc.BulkUpdateIssuesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.BulkUpdateIssues(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.BulkUpdateIssues(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	// Delete issue
	if err := protoserver.RegisterTool[*jirasvc.DeleteIssueInput, *jirasvc.DeleteIssueOutput](base.Registry, "jiraDeleteIssue", descDeleteIssue, func(ctx context.Context, in *jirasvc.DeleteIssueInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.DeleteIssue(ctx, in)
		if err != nil && strings.Contains(strings.ToLower(err.Error()), "missing jira credentials") {
			domain := svc.BaseDomain()
			prompt(ctx, in.Account.Alias, domain)
			time.Sleep(2 * time.Second)
			out, err = svc.DeleteIssue(ctx, in)
		}
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResult(svc, out)
	}); err != nil {
		return err
	}

	return nil
}

func urlQuery(s string) string { return strings.ReplaceAll(s, " ", "+") }

func newUUID() string { return uuid.New().String() }

// Helpers (mirrors other services)
func buildErrorResult(message string) (*schema.CallToolResult, *jsonrpc.Error) {
	return nil, jsonrpc.NewError(jsonrpc.InvalidParams, message, nil)
}

func buildSuccessResult(service *jirasvc.Service, payload any) (*schema.CallToolResult, *jsonrpc.Error) {
	if service.UseTextField() {
		b, _ := json.Marshal(payload)
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{schema.TextContent{Type: "text", Text: string(b)}}}, nil
	}
	return &schema.CallToolResult{StructuredContent: map[string]any{"result": payload}}, nil
}
