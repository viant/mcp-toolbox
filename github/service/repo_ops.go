package service

import (
	"context"
	"github.com/viant/mcp-toolbox/github/adapter"
)

// ListRepos lists repositories for the given account visibility/affiliation.
func (s *Service) ListRepos(ctx context.Context, in *ListReposInput, prompt func(string)) (*ListReposOutput, error) {
	alias := s.normalizeAlias(in.Account.Alias)
	if alias == "" {
		if inf, _ := s.inferAlias(ctx, in.Account.Domain, "", ""); inf != "" {
			alias = inf
		}
	}
	cli := adapter.New(in.Account.Domain)
	repos, err := withCredentialRetry(ctx, s, alias, in.Account.Domain, prompt, func(token string) ([]adapter.Repo, error) {
		return cli.ListRepos(ctx, token, in.Visibility, in.Affiliation, in.PerPage)
	})
	if err != nil {
		return nil, err
	}
	out := &ListReposOutput{}
	for _, v := range repos {
		out.Repos = append(out.Repos, Repo{ID: v.ID, Name: v.Name, FullName: v.FullName})
	}
	return out, nil
}

// ListRepoIssues lists issues for a repository.
func (s *Service) ListRepoIssues(ctx context.Context, in *ListRepoIssuesInput, prompt func(string)) (*ListRepoIssuesOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, _, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	alias, aerr := t.GetAlias(ctx, s)
	if aerr != nil {
		return nil, aerr
	}
	cli := adapter.New(domain)
	issues, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) ([]adapter.Issue, error) {
		return cli.ListRepoIssues(ctx, token, owner, name, in.State)
	})
	if err != nil {
		return nil, err
	}
	out := &ListRepoIssuesOutput{}
	for _, v := range issues {
		out.Issues = append(out.Issues, Issue{ID: v.ID, Number: v.Number, Title: v.Title, State: v.State})
	}
	return out, nil
}

// ListRepoPRs lists pull requests for a repository.
func (s *Service) ListRepoPRs(ctx context.Context, in *ListRepoPRsInput, prompt func(string)) (*ListRepoPRsOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, _, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	alias, aerr := t.GetAlias(ctx, s)
	if aerr != nil {
		return nil, aerr
	}
	cli := adapter.New(domain)
	pulls, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) ([]adapter.PullRequest, error) {
		return cli.ListRepoPRs(ctx, token, owner, name, in.State)
	})
	if err != nil {
		return nil, err
	}
	out := &ListRepoPRsOutput{}
	for _, v := range pulls {
		out.Pulls = append(out.Pulls, PullRequest{ID: v.ID, Number: v.Number, Title: v.Title, State: v.State})
	}
	return out, nil
}

// CreateIssue creates a new issue in a repository.
func (s *Service) CreateIssue(ctx context.Context, in *CreateIssueInput, prompt func(string)) (*CreateIssueOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, _, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	alias, aerr := t.GetAlias(ctx, s)
	if aerr != nil {
		return nil, aerr
	}
	cli := adapter.New(domain)
	issue, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (adapter.Issue, error) {
		return cli.CreateIssue(ctx, token, owner, name, in.Title, in.Body, in.Labels, in.Assignees)
	})
	if err != nil {
		return nil, err
	}
	return &CreateIssueOutput{Issue: Issue{ID: issue.ID, Number: issue.Number, Title: issue.Title, State: issue.State}}, nil
}

// CreatePR opens a pull request.
func (s *Service) CreatePR(ctx context.Context, in *CreatePRInput, prompt func(string)) (*CreatePROutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, _, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	alias, aerr := t.GetAlias(ctx, s)
	if aerr != nil {
		return nil, aerr
	}
	cli := adapter.New(domain)
	pr, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (adapter.PullRequest, error) {
		return cli.CreatePR(ctx, token, owner, name, in.Title, in.Body, in.Head, in.Base, in.Draft)
	})
	if err != nil {
		return nil, err
	}
	return &CreatePROutput{Pull: PullRequest{ID: pr.ID, Number: pr.Number, Title: pr.Title, State: pr.State}}, nil
}

// AddComment adds a comment to an issue or PR (PR comments use issue comments endpoint).
func (s *Service) AddComment(ctx context.Context, in *AddCommentInput, prompt func(string)) (*AddCommentOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, _, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	alias, aerr := t.GetAlias(ctx, s)
	if aerr != nil {
		return nil, aerr
	}
	cli := adapter.New(domain)
	cm, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (adapter.Comment, error) {
		return cli.AddComment(ctx, token, owner, name, in.IssueNumber, in.Body)
	})
	if err != nil {
		return nil, err
	}
	return &AddCommentOutput{Comment: Comment{ID: cm.ID, Body: cm.Body, User: cm.User, CreatedAt: cm.CreatedAt}}, nil
}

// ListComments lists comments for an issue or PR.
func (s *Service) ListComments(ctx context.Context, in *ListCommentsInput, prompt func(string)) (*ListCommentsOutput, error) {
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
	domain, owner, name, _, _, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	alias, aerr := t.GetAlias(ctx, s)
	if aerr != nil {
		return nil, aerr
	}
	cli := adapter.New(domain)
	items, err := withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) ([]adapter.Comment, error) {
		return cli.ListComments(ctx, token, owner, name, in.IssueNumber)
	})
	if err != nil {
		return nil, err
	}
	out := &ListCommentsOutput{}
	for _, v := range items {
		out.Comments = append(out.Comments, Comment{ID: v.ID, Body: v.Body, User: v.User, CreatedAt: v.CreatedAt})
	}
	return out, nil
}

// SearchIssues runs a GitHub issues/PRs search query.
func (s *Service) SearchIssues(ctx context.Context, in *SearchIssuesInput, prompt func(string)) (*SearchIssuesOutput, error) {
	alias := s.normalizeAlias(in.Account.Alias)
	if alias == "" {
		if inf, _ := s.inferAlias(ctx, in.Account.Domain, "", ""); inf != "" {
			alias = inf
		}
	}
	cli := adapter.New(in.Account.Domain)
	issues, err := withCredentialRetry(ctx, s, alias, in.Account.Domain, prompt, func(token string) ([]adapter.Issue, error) {
		return cli.SearchIssues(ctx, token, in.Query, in.PerPage)
	})
	if err != nil {
		return nil, err
	}
	out := &SearchIssuesOutput{}
	for _, it := range issues {
		out.Issues = append(out.Issues, Issue{ID: it.ID, Number: it.Number, Title: it.Title, State: it.State})
	}
	return out, nil
}
