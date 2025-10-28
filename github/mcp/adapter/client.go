package adapter

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    neturl "net/url"
)

// ErrUnauthorized is returned when GitHub responds with 401.
var ErrUnauthorized = fmt.Errorf("unauthorized")

// Client provides minimal GitHub REST API access used by MCP tools.
type Client struct {
    base string
    http *http.Client
}

// New creates a new Client for the given GitHub domain.
// If domain is empty or github.com, it targets public GitHub; otherwise Enterprise base.
func New(domain string) *Client {
    base := apiBase(domain)
    return &Client{base: base, http: http.DefaultClient}
}

// ListRepos lists repositories for the authenticated user.
func (c *Client) ListRepos(ctx context.Context, token, visibility, affiliation string, perPage int) ([]Repo, error) {
    q := neturl.Values{}
    if visibility != "" { q.Set("visibility", visibility) }
    if affiliation != "" { q.Set("affiliation", affiliation) }
    if perPage > 0 { q.Set("per_page", fmt.Sprintf("%d", perPage)) }
    url := c.base + "/user/repos"
    if enc := q.Encode(); enc != "" { url += "?" + enc }
    var items []struct{
        ID       int64  `json:"id"`
        Name     string `json:"name"`
        FullName string `json:"full_name"`
    }
    if err := c.getJSON(ctx, url, token, &items); err != nil { return nil, err }
    out := make([]Repo, 0, len(items))
    for _, v := range items { out = append(out, Repo{ID: v.ID, Name: v.Name, FullName: v.FullName}) }
    return out, nil
}

// ListRepoIssues lists issues for a repository.
func (c *Client) ListRepoIssues(ctx context.Context, token, owner, name, state string) ([]Issue, error) {
    q := neturl.Values{}
    if state != "" { q.Set("state", state) }
    url := fmt.Sprintf("%s/repos/%s/%s/issues", c.base, owner, name)
    if enc := q.Encode(); enc != "" { url += "?" + enc }
    var items []struct{
        ID     int64  `json:"id"`
        Number int    `json:"number"`
        Title  string `json:"title"`
        State  string `json:"state"`
    }
    if err := c.getJSON(ctx, url, token, &items); err != nil { return nil, err }
    out := make([]Issue, 0, len(items))
    for _, v := range items { out = append(out, Issue{ID: v.ID, Number: v.Number, Title: v.Title, State: v.State}) }
    return out, nil
}

// ListRepoPRs lists pull requests for a repository.
func (c *Client) ListRepoPRs(ctx context.Context, token, owner, name, state string) ([]PullRequest, error) {
    q := neturl.Values{}
    if state != "" { q.Set("state", state) }
    url := fmt.Sprintf("%s/repos/%s/%s/pulls", c.base, owner, name)
    if enc := q.Encode(); enc != "" { url += "?" + enc }
    var items []struct{
        ID     int64  `json:"id"`
        Number int    `json:"number"`
        Title  string `json:"title"`
        State  string `json:"state"`
    }
    if err := c.getJSON(ctx, url, token, &items); err != nil { return nil, err }
    out := make([]PullRequest, 0, len(items))
    for _, v := range items { out = append(out, PullRequest{ID: v.ID, Number: v.Number, Title: v.Title, State: v.State}) }
    return out, nil
}

func (c *Client) getJSON(ctx context.Context, url, token string, out any) error {
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Accept", "application/vnd.github+json")
    resp, err := c.http.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode == http.StatusUnauthorized {
        return ErrUnauthorized
    }
    if resp.StatusCode >= 300 {
        return fmt.Errorf("request failed: %s", resp.Status)
    }
    return json.NewDecoder(resp.Body).Decode(out)
}

// Minimal types mirrored in MCP package for decoupling.
type Repo struct{ ID int64; Name, FullName string }
type Issue struct{ ID int64; Number int; Title, State string }
type PullRequest struct{ ID int64; Number int; Title, State string }

func apiBase(domain string) string {
    if domain == "" || domain == "github.com" { return "https://api.github.com" }
    return "https://" + domain + "/api/v3"
}

