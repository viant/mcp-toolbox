package mcp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"regexp"
	"strings"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	protoserver "github.com/viant/mcp-protocol/server"
	ghservice "github.com/viant/mcp-toolbox/github/service"
)

//go:embed tools/listRepos.md
var descListRepos string

//go:embed tools/listRepoIssues.md
var descListIssues string

//go:embed tools/listRepoPRs.md
var descListPRs string

//go:embed tools/createIssue.md
var descCreateIssue string

//go:embed tools/createPR.md
var descCreatePR string

//go:embed tools/addComment.md
var descAddComment string

//go:embed tools/listComments.md
var descListComments string

//go:embed tools/searchIssues.md
var descSearchIssues string

//go:embed tools/checkoutRepo.md
var descCheckoutRepo string

//go:embed tools/listRepoPath.md
var descListRepoPath string

//go:embed tools/downloadRepoFile.md
var descDownloadRepoFile string

//go:embed tools/findFilesPreview.md
var descFindFilesPreview string

// Types moved to types.go

func logToolStart(name string) time.Time {
	ts := time.Now()
	fmt.Printf("[MCP][%s] START tool=%s\n", ts.Format(time.RFC3339Nano), name)
	return ts
}

func logToolEnd(name string, start time.Time, err error) {
	dur := time.Since(start)
	if err != nil {
		fmt.Printf("[MCP][%s] END tool=%s dur=%s err=%v\n", time.Now().Format(time.RFC3339Nano), name, dur, err)
	} else {
		fmt.Printf("[MCP][%s] END tool=%s dur=%s ok\n", time.Now().Format(time.RFC3339Nano), name, dur)
	}
}

// startToolPending prints a start line with summarized args and returns a stopper that prints end.
func startToolPending(name string, args any, start time.Time) func() {
	fmt.Printf("[MCP] ARGS tool=%s args=%s\n", name, summarizeArgs(args))
	return func() {}
}

func logToolNS(h *Handler, name string, ctx context.Context) {
	if h == nil {
		return
	}
	if d, err := h.nsProvider.Namespace(ctx); err == nil {
		fmt.Printf("[MCP] NS tool=%s ns=%s\n", name, d.Name)
	}
}

func summarizeArgs(args any) string {
	if args == nil {
		return "{}"
	}
	b, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	s := string(b)
	// redact common large/sensitive fields
	s = regexp.MustCompile(`"body"\s*:\s*".*?"`).ReplaceAllString(s, `"body":"[REDACTED]"`)
	s = regexp.MustCompile(`"sedScripts"\s*:\s*\[[^\]]*\]`).ReplaceAllString(s, `"sedScripts":["[REDACTED]"]`)
	const max = 512
	if len(s) > max {
		return s[:max] + fmt.Sprintf("...(+%d)", len(s)-max)
	}
	return s
}

func registerTools(base *protoserver.DefaultHandler, h *Handler) error {
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
			// Fire-and-forget to avoid blocking the triggering tool call on transport/UI delays.
			go func() {
				// Short timeout to prevent long blocking if client/UI is slow.
				ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				fmt.Printf("[MCP] ELICIT SEND id=%s url=%s\n", elicitID, u)
				_, _ = ops.Elicit(ctx2, &jsonrpc.TypedRequest[*schema.ElicitRequest]{Request: &schema.ElicitRequest{
					Params: schema.ElicitRequestParams{ElicitationId: elicitID, Message: text, Mode: string(schema.ElicitRequestParamsModeUrl), Url: u},
				}})
			}()
		}
	}

	// List repositories
	if err := protoserver.RegisterTool[*ghservice.ListReposInput, *ghservice.ListReposOutput](base.Registry, "listRepos", descListRepos, func(ctx context.Context, in *ghservice.ListReposInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("listRepos")
		stop := startToolPending("listRepos", in, start)
		defer stop()
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "listRepos", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.ListRepos(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("listRepos", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("listRepos", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List repo issues
	if err := protoserver.RegisterTool[*ghservice.ListRepoIssuesInput, *ghservice.ListRepoIssuesOutput](base.Registry, "listRepoIssues", descListIssues, func(ctx context.Context, in *ghservice.ListRepoIssuesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("listRepoIssues")
		stop := startToolPending("listRepoIssues", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("listRepoIssues", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "listRepoIssues", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.ListRepoIssues(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("listRepoIssues", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("listRepoIssues", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List repo pull requests
	if err := protoserver.RegisterTool[*ghservice.ListRepoPRsInput, *ghservice.ListRepoPRsOutput](base.Registry, "listRepoPRs", descListPRs, func(ctx context.Context, in *ghservice.ListRepoPRsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("listRepoPRs")
		stop := startToolPending("listRepoPRs", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("listRepoPRs", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "listRepoPRs", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.ListRepoPRs(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("listRepoPRs", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("listRepoPRs", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Create issue
	if err := protoserver.RegisterTool[*ghservice.CreateIssueInput, *ghservice.CreateIssueOutput](base.Registry, "createIssue", descCreateIssue, func(ctx context.Context, in *ghservice.CreateIssueInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("createIssue")
		stop := startToolPending("createIssue", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("createIssue", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.Title == "" {
			logToolEnd("createIssue", start, fmt.Errorf("missing title"))
			return buildErrorResult("title is required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "createIssue", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.CreateIssue(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("createIssue", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("createIssue", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Create PR
	if err := protoserver.RegisterTool[*ghservice.CreatePRInput, *ghservice.CreatePROutput](base.Registry, "createPR", descCreatePR, func(ctx context.Context, in *ghservice.CreatePRInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("createPR")
		stop := startToolPending("createPR", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("createPR", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.Title == "" || in.Head == "" || in.Base == "" {
			logToolEnd("createPR", start, fmt.Errorf("missing title/head/base"))
			return buildErrorResult("title, head, and base are required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "createPR", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.CreatePR(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("createPR", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("createPR", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Add comment
	if err := protoserver.RegisterTool[*ghservice.AddCommentInput, *ghservice.AddCommentOutput](base.Registry, "addComment", descAddComment, func(ctx context.Context, in *ghservice.AddCommentInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("addComment")
		stop := startToolPending("addComment", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("addComment", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.IssueNumber <= 0 {
			logToolEnd("addComment", start, fmt.Errorf("invalid issueNumber"))
			return buildErrorResult("issueNumber must be > 0")
		}
		if in.Body == "" {
			logToolEnd("addComment", start, fmt.Errorf("missing body"))
			return buildErrorResult("body is required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "addComment", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.AddComment(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("addComment", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("addComment", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List comments
	if err := protoserver.RegisterTool[*ghservice.ListCommentsInput, *ghservice.ListCommentsOutput](base.Registry, "listComments", descListComments, func(ctx context.Context, in *ghservice.ListCommentsInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("listComments")
		stop := startToolPending("listComments", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("listComments", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.IssueNumber <= 0 {
			logToolEnd("listComments", start, fmt.Errorf("invalid issueNumber"))
			return buildErrorResult("issueNumber must be > 0")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "listComments", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.ListComments(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("listComments", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("listComments", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Search issues/PRs
	if err := protoserver.RegisterTool[*ghservice.SearchIssuesInput, *ghservice.SearchIssuesOutput](base.Registry, "searchIssues", descSearchIssues, func(ctx context.Context, in *ghservice.SearchIssuesInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("searchIssues")
		stop := startToolPending("searchIssues", in, start)
		defer stop()
		if strings.TrimSpace(in.Query) == "" {
			logToolEnd("searchIssues", start, fmt.Errorf("missing query"))
			return buildErrorResult("query is required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "searchIssues", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.SearchIssues(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("searchIssues", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("searchIssues", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Checkout repository (clone + optional branch/commit)
	if err := protoserver.RegisterTool[*ghservice.CheckoutRepoInput, *ghservice.CheckoutRepoOutput](base.Registry, "checkoutRepo", descCheckoutRepo, func(ctx context.Context, in *ghservice.CheckoutRepoInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("checkoutRepo")
		stop := startToolPending("checkoutRepo", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("checkoutRepo", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "checkoutRepo", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.CheckoutRepo(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("checkoutRepo", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("checkoutRepo", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// List repo path (without clone)
	if err := protoserver.RegisterTool[*ghservice.ListRepoInput, *ghservice.ListRepoOutput](base.Registry, "listRepo", descListRepoPath, func(ctx context.Context, in *ghservice.ListRepoInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("listRepo")
		stop := startToolPending("listRepo", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("listRepo", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "listRepo", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.ListRepoPath(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("listRepo", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("listRepo", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Download repo file (without clone)
	if err := protoserver.RegisterTool[*ghservice.DownloadInput, *ghservice.DownloadOutput](base.Registry, "download", descDownloadRepoFile, func(ctx context.Context, in *ghservice.DownloadInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("download")
		stop := startToolPending("download", in, start)
		defer stop()
		if (in.Repo.Owner == "" || in.Repo.Name == "") && strings.TrimSpace(in.URL) == "" {
			logToolEnd("download", start, fmt.Errorf("missing repo or url"))
			return buildErrorResult("repo.owner and repo.name or url are required")
		}
		if in.Path == "" {
			logToolEnd("download", start, fmt.Errorf("missing path"))
			return buildErrorResult("path is required")
		}
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "download", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		cid := newUUID()
		ctxNS = ghservice.WithCID(ctxNS, cid)
		fmt.Printf("[MCP] CID tool=download cid=%s path=%s\n", cid, in.Path)
		out, err := svc.DownloadRepoFile(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("download", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("download", start, nil)
		return buildSuccessResultOut(svc, out)
	}); err != nil {
		return err
	}

	// Find files with preview (no apply), supports sed-like preview on snapshot
	if err := protoserver.RegisterTool[*ghservice.FindFilesPreviewInput, *ghservice.FindFilesPreviewOutput](base.Registry, "searchRepoContent", descFindFilesPreview, func(ctx context.Context, in *ghservice.FindFilesPreviewInput) (*schema.CallToolResult, *jsonrpc.Error) {
		start := logToolStart("searchRepoContent")
		stop := startToolPending("searchRepoContent", in, start)
		defer stop()
		ctxNS, svc, rerr := h.resolveService(ctx)
		logToolNS(h, "searchRepoContent", ctxNS)
		if rerr != nil {
			return buildErrorResult("resolve namespace: " + rerr.Error())
		}
		out, err := svc.SearchRepoContent(ctxNS, in, msgPrompt(ctxNS))
		if err != nil {
			logToolEnd("searchRepoContent", start, err)
			return buildErrorResult(err.Error())
		}
		logToolEnd("searchRepoContent", start, nil)
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
