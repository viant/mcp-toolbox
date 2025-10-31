package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"regexp"
	"strings"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	ghservice "github.com/viant/mcp-toolbox/github/service"
)

//go:embed tools/githubListRepos.md
var descListRepos string

//go:embed tools/githubListRepoIssues.md
var descListIssues string

//go:embed tools/githubListRepoPRs.md
var descListPRs string

//go:embed tools/githubCreateIssue.md
var descCreateIssue string

//go:embed tools/githubCreatePR.md
var descCreatePR string

//go:embed tools/githubAddComment.md
var descAddComment string

//go:embed tools/githubListComments.md
var descListComments string

//go:embed tools/githubSearchIssues.md
var descSearchIssues string

//go:embed tools/githubCheckoutRepo.md
var descCheckoutRepo string

//go:embed tools/githubListRepoPath.md
var descListRepoPath string

//go:embed tools/githubDownloadRepoFile.md
var descDownloadRepoFile string

// Types moved to types.go

func registerTools(base *protoserver.DefaultHandler, h *Handler) error {
	svc := h.service
	ops := h.ops

	// Helper to surface device login prompt via elicitation.
	msgPrompt := func(ctx context.Context) func(string) {
		if ops == nil || !ops.Implements(schema.MethodElicitationCreate) {
			return nil
		}
		return func(msg string) {
			u := extractURL(msg)
			code := extractCode(msg)
			text := buildPromptMessage(u, code)
			elicitID := newUUID()
			_, _ = ops.Elicit(ctx, &jsonrpc.TypedRequest[*schema.ElicitRequest]{Request: &schema.ElicitRequest{
				Params: schema.ElicitRequestParams{ElicitationId: elicitID, Message: text, Mode: string(schema.ElicitRequestParamsModeUrl), Url: u},
			}})
		}
	}

	// List repositories
	if err := protoserver.RegisterTool[*ghservice.ListReposInput, *ghservice.ListReposOutput](base.Registry, "githubListRepos", descListRepos, func(ctx context.Context, in *ghservice.ListReposInput) (*schema.CallToolResult, *jsonrpc.Error) {
		out, err := svc.ListRepos(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List repo issues
	if err := protoserver.RegisterTool[*ghservice.ListRepoIssuesInput, *ghservice.ListRepoIssuesOutput](base.Registry, "githubListRepoIssues", descListIssues, func(ctx context.Context, in *ghservice.ListRepoIssuesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		out, err := svc.ListRepoIssues(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List repo pull requests
	if err := protoserver.RegisterTool[*ghservice.ListRepoPRsInput, *ghservice.ListRepoPRsOutput](base.Registry, "githubListRepoPRs", descListPRs, func(ctx context.Context, in *ghservice.ListRepoPRsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		out, err := svc.ListRepoPRs(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Create issue
	if err := protoserver.RegisterTool[*ghservice.CreateIssueInput, *ghservice.CreateIssueOutput](base.Registry, "githubCreateIssue", descCreateIssue, func(ctx context.Context, in *ghservice.CreateIssueInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.Title == "" {
			return buildErrorResult("title is required")
		}
		out, err := svc.CreateIssue(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Create PR
	if err := protoserver.RegisterTool[*ghservice.CreatePRInput, *ghservice.CreatePROutput](base.Registry, "githubCreatePR", descCreatePR, func(ctx context.Context, in *ghservice.CreatePRInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.Title == "" || in.Head == "" || in.Base == "" {
			return buildErrorResult("title, head, and base are required")
		}
		out, err := svc.CreatePR(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Add comment
	if err := protoserver.RegisterTool[*ghservice.AddCommentInput, *ghservice.AddCommentOutput](base.Registry, "githubAddComment", descAddComment, func(ctx context.Context, in *ghservice.AddCommentInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.IssueNumber <= 0 {
			return buildErrorResult("issueNumber must be > 0")
		}
		if in.Body == "" {
			return buildErrorResult("body is required")
		}
		out, err := svc.AddComment(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List comments
	if err := protoserver.RegisterTool[*ghservice.ListCommentsInput, *ghservice.ListCommentsOutput](base.Registry, "githubListComments", descListComments, func(ctx context.Context, in *ghservice.ListCommentsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.IssueNumber <= 0 {
			return buildErrorResult("issueNumber must be > 0")
		}
		out, err := svc.ListComments(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Search issues/PRs
	if err := protoserver.RegisterTool[*ghservice.SearchIssuesInput, *ghservice.SearchIssuesOutput](base.Registry, "githubSearchIssues", descSearchIssues, func(ctx context.Context, in *ghservice.SearchIssuesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if strings.TrimSpace(in.Query) == "" {
			return buildErrorResult("query is required")
		}
		out, err := svc.SearchIssues(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Checkout repository (clone + optional branch/commit)
	if err := protoserver.RegisterTool[*ghservice.CheckoutRepoInput, *ghservice.CheckoutRepoOutput](base.Registry, "githubCheckoutRepo", descCheckoutRepo, func(ctx context.Context, in *ghservice.CheckoutRepoInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		out, err := svc.CheckoutRepo(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List repo path (without clone)
	if err := protoserver.RegisterTool[*ghservice.ListRepoInput, *ghservice.ListRepoOutput](base.Registry, "listRepo", descListRepoPath, func(ctx context.Context, in *ghservice.ListRepoInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		out, err := svc.ListRepoPath(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Download repo file (without clone)
	if err := protoserver.RegisterTool[*ghservice.DownloadInput, *ghservice.DownloadOutput](base.Registry, "download", descDownloadRepoFile, func(ctx context.Context, in *ghservice.DownloadInput) (*schema.CallToolResult, *jsonrpc.Error) {
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.Path == "" {
			return buildErrorResult("path is required")
		}
		out, err := svc.DownloadRepoFile(ctx, in, msgPrompt(ctx))
		if err != nil {
			return buildErrorResult(err.Error())
		}
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	return nil
}

func buildErrorResult(message string) (*schema.CallToolResult, *jsonrpc.Error) {
	return nil, jsonrpc.NewError(jsonrpc.InvalidParams, message, nil)
}

func buildSuccessResultOut(service *ghservice.Service, payload any) (*schema.CallToolResult, *jsonrpc.Error) {
	if service.UseTextField() {
		b, _ := json.Marshal(payload)
		return &schema.CallToolResult{Content: []schema.CallToolResultContentElem{{Type: "text", Text: string(b)}}}, nil
	}
	return &schema.CallToolResult{StructuredContent: map[string]any{"result": payload}}, nil
}

func newUUID() string { return ghsvcUUID() }

// defer actual uuid import to ghsvc util to keep tool lean
func ghsvcUUID() string { return ghservice.NewUUID() }

// Helpers to extract URL/code from device prompt text.
func extractURL(msg string) string {
	if m := regexp.MustCompile(`https?://[^\s]+`).FindString(msg); m != "" {
		return m
	}
	return "https://github.com/login/device"
}
func extractCode(msg string) string {
	if m := regexp.MustCompile(`(?i)code\s+([A-Z0-9-]+)`).FindStringSubmatch(msg); len(m) == 2 {
		return m[1]
	}
	return ""
}

// buildPromptMessage creates a concise, user-friendly message without exposing full URLs.
func buildPromptMessage(u, code string) string {
	if strings.TrimSpace(code) != "" {
		return fmt.Sprintf("Open GitHub and enter code: %s", code)
	}
	// Try to derive a friendly target from OOB URL params
	if p, err := neturl.Parse(u); err == nil {
		q := p.Query()
		if repo := q.Get("url"); repo != "" {
			return fmt.Sprintf("Authorize access for %s", repo)
		}
		if domain := q.Get("domain"); domain != "" {
			return fmt.Sprintf("Authorize GitHub access for %s", domain)
		}
		if host := p.Host; host != "" {
			return fmt.Sprintf("Open authentication on %s", host)
		}
	}
	return "Additional input required"
}

// apiBase removed from this file; handled by adapter.
