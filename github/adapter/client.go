package adapter

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"strings"
)

var (
	// Backward-compat alias (used by some callers)
	ErrUnauthorized   = errors.New("unauthorized")
	ErrBadCredentials = errors.New("bad_credentials")
	ErrRateLimited    = errors.New("rate_limited")
	ErrForbidden      = errors.New("forbidden")
	ErrSSORequired    = errors.New("sso_required")
	ErrNotFound       = errors.New("not_found")
)

func classify(resp *http.Response, op string) error {
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return ErrBadCredentials
	case http.StatusForbidden:
		if strings.Contains(strings.ToLower(resp.Header.Get("X-GitHub-SSO")), "required") {
			return ErrSSORequired
		}
		if strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining")) == "0" {
			return ErrRateLimited
		}
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	default:
		if resp.StatusCode >= 300 {
			return fmt.Errorf("%s failed: %s", op, resp.Status)
		}
		return nil
	}
}

type Client struct{ apiBase string }

func New(domain string) *Client {
	if domain == "" || domain == "github.com" {
		return &Client{apiBase: "https://api.github.com"}
	}
	return &Client{apiBase: "https://" + domain + "/api/v3"}
}

// internal HTTP helpers to reduce duplication across API calls
func (c *Client) doGET(ctx context.Context, url, token, accept string) (*http.Response, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", authBasic(token))
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	} else {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	return http.DefaultClient.Do(req)
}

func (c *Client) doPOSTJSON(ctx context.Context, url, token string, payload any) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = strings.NewReader(string(b))
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", authBasic(token))
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	return http.DefaultClient.Do(req)
}

type Repo struct {
	ID             int64
	Name, FullName string
}
type Issue struct {
	ID           int64
	Number       int
	Title, State string
}
type PullRequest struct {
	ID           int64
	Number       int
	Title, State string
}
type Comment struct {
	ID                    int64
	Body, User, CreatedAt string
}

// ContentItem represents a file or directory in the repo contents API.
type ContentItem struct {
	Type        string `json:"type"` // "file" or "dir"
	Name        string `json:"name"`
	Path        string `json:"path"`
	Sha         string `json:"sha"`
	Size        int    `json:"size"`
	DownloadURL string `json:"download_url"`
}

// ValidateRef checks whether a ref (branch/tag/sha) is usable with the Contents API
// by probing the repository root contents with the supplied ref.
// It returns nil on any 2xx response, ErrUnauthorized on 401, and an error otherwise.
func (c *Client) ValidateRef(ctx context.Context, token, owner, name, ref string) error {
	if strings.TrimSpace(ref) == "" {
		return fmt.Errorf("empty ref")
	}
	url := fmt.Sprintf("%s/repos/%s/%s/contents", c.apiBase, owner, name)
	if ref != "" {
		url += "?ref=" + neturl.QueryEscape(ref)
	}
	resp, err := c.doGET(ctx, url, token, "application/vnd.github+json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "validate ref"); err2 != nil {
		return err2
	}
	return nil
}

// Trees API types
type TreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"` // "blob" | "tree" | "commit" (submodule)
	Size int    `json:"size,omitempty"`
	Sha  string `json:"sha"`
	Url  string `json:"url"`
}

// GetBlob fetches blob content by SHA via the Git Data API.
func (c *Client) GetBlob(ctx context.Context, token, owner, name, sha string) ([]byte, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/blobs/%s", c.apiBase, owner, name, sha)
	// Try raw first
	resp, err := c.doGET(ctx, url, token, "application/vnd.github.raw")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 300 {
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	_ = classify(resp, "get blob")
	resp.Body.Close()
	// Fallback JSON base64
	resp2, err := c.doGET(ctx, url, token, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	if err2 := classify(resp2, "get blob"); err2 != nil {
		return nil, err2
	}
	var obj struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&obj); err != nil {
		return nil, err
	}
	b64 := strings.ReplaceAll(obj.Content, "\n", "")
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// GetCommitTreeSHA resolves a ref (branch/tag/commit) to its tree SHA via commits API.
func (c *Client) GetCommitTreeSHA(ctx context.Context, token, owner, name, ref string) (string, error) {
	// try plain ref first
	try := func(r string) (string, int, error) {
		url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", c.apiBase, owner, name, r)
		resp, err := c.doGET(ctx, url, token, "application/vnd.github+json")
		if err != nil {
			return "", 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			return "", resp.StatusCode, ErrUnauthorized
		}
		if resp.StatusCode >= 300 {
			return "", resp.StatusCode, fmt.Errorf("get commit failed: %s", resp.Status)
		}
		var payload struct {
			Commit struct {
				Tree struct {
					Sha string `json:"sha"`
				} `json:"tree"`
			} `json:"commit"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return "", resp.StatusCode, err
		}
		if payload.Commit.Tree.Sha == "" {
			return "", resp.StatusCode, fmt.Errorf("commit tree SHA not found for ref %s", r)
		}
		return payload.Commit.Tree.Sha, resp.StatusCode, nil
	}
	// plain branch/tag/sha
	if sha, sc, err := try(ref); err == nil {
		return sha, nil
	} else {
		// On 422, some GHEs require explicit heads/ prefix
		if sc == http.StatusUnprocessableEntity && !strings.Contains(ref, "/") {
			if sha, _, err2 := try("heads/" + ref); err2 == nil {
				return sha, nil
			}
			if sha, _, err3 := try("refs/heads/" + ref); err3 == nil {
				return sha, nil
			}
		}
		return "", err
	}
}

// GetRepoDefaultBranch returns the default branch name (e.g., "main" or "master").
func (c *Client) GetRepoDefaultBranch(ctx context.Context, token, owner, name string) (string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", c.apiBase, owner, name)
	resp, err := c.doGET(ctx, url, token, "application/vnd.github+json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "get repo"); err2 != nil {
		return "", err2
	}
	var payload struct {
		DefaultBranch string `json:"default_branch"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", err
	}
	if payload.DefaultBranch == "" {
		return "", fmt.Errorf("default_branch not found")
	}
	return payload.DefaultBranch, nil
}

// GetTreeRecursive fetches a full tree listing with recursive=1. Returns entries and whether it was truncated.
func (c *Client) GetTreeRecursive(ctx context.Context, token, owner, name, treeSha string) ([]TreeEntry, bool, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/git/trees/%s?recursive=1", c.apiBase, owner, name, treeSha)
	resp, err := c.doGET(ctx, url, token, "application/vnd.github+json")
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "get tree"); err2 != nil {
		return nil, false, err2
	}
	var payload struct {
		Tree      []TreeEntry `json:"tree"`
		Truncated bool        `json:"truncated"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, err
	}
	return payload.Tree, payload.Truncated, nil
}

func (c *Client) ListRepos(ctx context.Context, token, visibility, affiliation string, perPage int) ([]Repo, error) {
	q := neturl.Values{}
	if visibility != "" {
		q.Set("visibility", visibility)
	}
	if affiliation != "" {
		q.Set("affiliation", affiliation)
	}
	if perPage > 0 {
		q.Set("per_page", fmt.Sprintf("%d", perPage))
	}
	url := c.apiBase + "/user/repos"
	if enc := q.Encode(); enc != "" {
		url += "?" + enc
	}
	resp, err := c.doGET(ctx, url, token, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "list repos"); err2 != nil {
		return nil, err2
	}
	var items []struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	out := make([]Repo, 0, len(items))
	for _, v := range items {
		out = append(out, Repo{ID: v.ID, Name: v.Name, FullName: v.FullName})
	}
	return out, nil
}

// ValidateToken performs a lightweight call to verify that provided credentials are valid.
// It calls the /user endpoint which requires an authenticated token.
func (c *Client) ValidateToken(ctx context.Context, token string) error {
	url := c.apiBase + "/user"
	resp, err := c.doGET(ctx, url, token, "application/vnd.github+json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "validate token"); err2 != nil {
		return err2
	}
	return nil
}

func (c *Client) ListRepoIssues(ctx context.Context, token, owner, name, state string) ([]Issue, error) {
	q := neturl.Values{}
	if state != "" {
		q.Set("state", state)
	}
	url := fmt.Sprintf("%s/repos/%s/%s/issues", c.apiBase, owner, name)
	if enc := q.Encode(); enc != "" {
		url += "?" + enc
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", authBasic(token))
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "list issues"); err2 != nil {
		return nil, err2
	}
	var items []struct {
		ID     int64  `json:"id"`
		Number int    `json:"number"`
		Title  string `json:"title"`
		State  string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	out := make([]Issue, 0, len(items))
	for _, v := range items {
		out = append(out, Issue{ID: v.ID, Number: v.Number, Title: v.Title, State: v.State})
	}
	return out, nil
}

func (c *Client) ListRepoPRs(ctx context.Context, token, owner, name, state string) ([]PullRequest, error) {
	q := neturl.Values{}
	if state != "" {
		q.Set("state", state)
	}
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", c.apiBase, owner, name)
	if enc := q.Encode(); enc != "" {
		url += "?" + enc
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", authBasic(token))
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list pulls failed: %s", resp.Status)
	}
	var items []struct {
		ID     int64  `json:"id"`
		Number int    `json:"number"`
		Title  string `json:"title"`
		State  string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	out := make([]PullRequest, 0, len(items))
	for _, v := range items {
		out = append(out, PullRequest{ID: v.ID, Number: v.Number, Title: v.Title, State: v.State})
	}
	return out, nil
}

func (c *Client) CreateIssue(ctx context.Context, token, owner, name, title, body string, labels, assignees []string) (Issue, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/issues", c.apiBase, owner, name)
	payload := map[string]any{"title": title}
	if body != "" {
		payload["body"] = body
	}
	if len(labels) > 0 {
		payload["labels"] = labels
	}
	if len(assignees) > 0 {
		payload["assignees"] = assignees
	}
	resp, err := c.doPOSTJSON(ctx, url, token, payload)
	if err != nil {
		return Issue{}, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "create issue"); err2 != nil {
		return Issue{}, err2
	}
	var it struct {
		ID           int64  `json:"id"`
		Number       int    `json:"number"`
		Title, State string `json:"title","state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&it); err != nil {
		return Issue{}, err
	}
	return Issue{ID: it.ID, Number: it.Number, Title: it.Title, State: it.State}, nil
}

func (c *Client) CreatePR(ctx context.Context, token, owner, name, title, body, head, base string, draft bool) (PullRequest, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/pulls", c.apiBase, owner, name)
	payload := map[string]any{"title": title, "head": head, "base": base}
	if body != "" {
		payload["body"] = body
	}
	if draft {
		payload["draft"] = true
	}
	resp, err := c.doPOSTJSON(ctx, url, token, payload)
	if err != nil {
		return PullRequest{}, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "create pull request"); err2 != nil {
		return PullRequest{}, err2
	}
	var it struct {
		ID           int64  `json:"id"`
		Number       int    `json:"number"`
		Title, State string `json:"title","state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&it); err != nil {
		return PullRequest{}, err
	}
	return PullRequest{ID: it.ID, Number: it.Number, Title: it.Title, State: it.State}, nil
}

func (c *Client) AddComment(ctx context.Context, token, owner, name string, issueNumber int, body string) (Comment, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", c.apiBase, owner, name, issueNumber)
	resp, err := c.doPOSTJSON(ctx, url, token, map[string]any{"body": body})
	if err != nil {
		return Comment{}, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "add comment"); err2 != nil {
		return Comment{}, err2
	}
	var it struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
		User struct {
			Login string `json:"login"`
		} `json:"user"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&it); err != nil {
		return Comment{}, err
	}
	return Comment{ID: it.ID, Body: it.Body, User: it.User.Login, CreatedAt: it.CreatedAt}, nil
}

func (c *Client) ListComments(ctx context.Context, token, owner, name string, issueNumber int) ([]Comment, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", c.apiBase, owner, name, issueNumber)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", authBasic(token))
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "list comments"); err2 != nil {
		return nil, err2
	}
	var items []struct {
		ID   int64  `json:"id"`
		Body string `json:"body"`
		User struct {
			Login string `json:"login"`
		} `json:"user"`
		CreatedAt string `json:"created_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, err
	}
	out := make([]Comment, 0, len(items))
	for _, v := range items {
		out = append(out, Comment{ID: v.ID, Body: v.Body, User: v.User.Login, CreatedAt: v.CreatedAt})
	}
	return out, nil
}

func (c *Client) SearchIssues(ctx context.Context, token, query string, perPage int) ([]Issue, error) {
	q := neturl.Values{}
	q.Set("q", query)
	if perPage > 0 {
		q.Set("per_page", fmt.Sprintf("%d", perPage))
	}
	url := c.apiBase + "/search/issues?" + q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", authBasic(token))
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "search issues"); err2 != nil {
		return nil, err2
	}
	var result struct {
		Items []struct {
			ID     int64  `json:"id"`
			Number int    `json:"number"`
			Title  string `json:"title"`
			State  string `json:"state"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	out := make([]Issue, 0, len(result.Items))
	for _, it := range result.Items {
		out = append(out, Issue{ID: it.ID, Number: it.Number, Title: it.Title, State: it.State})
	}
	return out, nil
}

// ListContents lists directory entries at path, or returns a single item if path points to a file.
func (c *Client) ListContents(ctx context.Context, token, owner, name, path, ref string) ([]ContentItem, error) {
	var url string
	if strings.TrimSpace(path) == "" {
		url = fmt.Sprintf("%s/repos/%s/%s/contents", c.apiBase, owner, name)
	} else {
		url = fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.apiBase, owner, name, path)
	}
	if ref != "" {
		url += "?ref=" + neturl.QueryEscape(ref)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", authBasic(token))
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return nil, ErrUnauthorized
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list contents failed: %s", resp.Status)
	}
	// Could be array (dir) or object (file)
	var arr []ContentItem
	if err := json.NewDecoder(resp.Body).Decode(&arr); err == nil {
		return arr, nil
	}
	// Reset decode by re-issuing the request
	resp2, err := c.doGET(ctx, url, token, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	if err2 := classify(resp2, "list contents"); err2 != nil {
		return nil, err2
	}
	var obj ContentItem
	if err := json.NewDecoder(resp2.Body).Decode(&obj); err != nil {
		return nil, err
	}
	return []ContentItem{obj}, nil
}

// GetFileContent fetches raw file bytes via the contents API.
func (c *Client) GetFileContent(ctx context.Context, token, owner, name, path, ref string) ([]byte, error) {
	var url string
	if strings.TrimSpace(path) == "" {
		url = fmt.Sprintf("%s/repos/%s/%s/contents", c.apiBase, owner, name)
	} else {
		url = fmt.Sprintf("%s/repos/%s/%s/contents/%s", c.apiBase, owner, name, path)
	}
	if ref != "" {
		url += "?ref=" + neturl.QueryEscape(ref)
	}
	// First try raw media type
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", authBasic(token))
	req.Header.Set("Accept", "application/vnd.github.raw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, ErrUnauthorized
	}
	if resp.StatusCode < 300 {
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	// Some GHE deployments respond 404/415 for raw; fall back to JSON and decode base64 content
	resp.Body.Close()
	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req2.Header.Set("Authorization", authBasic(token))
	req2.Header.Set("Accept", "application/vnd.github+json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		return nil, err
	}
	defer resp2.Body.Close()
	if err2 := classify(resp2, "get content"); err2 != nil {
		return nil, err2
	}
	var obj struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&obj); err != nil {
		return nil, err
	}
	if obj.Content == "" {
		return nil, fmt.Errorf("empty content payload")
	}
	// GitHub may include newlines in base64 content
	b64 := strings.ReplaceAll(obj.Content, "\n", "")
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func authBasic(token string) string {
	// If token looks like "username:password", use it directly; else treat as PAT.
	if strings.Contains(token, ":") {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(token))
	}
	creds := "x-access-token:" + token
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

// RepoInfo carries minimal repo metadata needed for permission/visibility checks.
type RepoInfo struct {
	Private    bool   `json:"private"`
	Visibility string `json:"visibility,omitempty"`
}

// GetRepo fetches repository metadata; returns ErrUnauthorized on 401.
func (c *Client) GetRepo(ctx context.Context, token, owner, name string) (RepoInfo, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", c.apiBase, owner, name)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", authBasic(token))
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return RepoInfo{}, err
	}
	defer resp.Body.Close()
	if err2 := classify(resp, "get repo"); err2 != nil {
		return RepoInfo{}, err2
	}
	var out RepoInfo
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return RepoInfo{}, err
	}
	return out, nil
}
