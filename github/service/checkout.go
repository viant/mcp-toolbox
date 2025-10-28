package service

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    git "github.com/go-git/go-git/v6"
    "github.com/go-git/go-git/v6/plumbing"
    gitHttp "github.com/go-git/go-git/v6/plumbing/transport/http"
)

// CheckoutRepo clones a repository and optionally checks out a branch or commit.
func (s *Service) CheckoutRepo(ctx context.Context, in *CheckoutRepoInput, prompt func(string)) (*CheckoutRepoOutput, error) {
    if in == nil { return nil, fmt.Errorf("input is nil") }
    t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo}
    domain, owner, name, _, alias, err := t.Init(s)
    if err != nil { return nil, err }
    if alias == "" { return nil, fmt.Errorf("account.alias is required") }

    ns, _ := s.auth.Namespace(ctx)
    if ns == "" { ns = "default" }
    token := s.loadTokenPreferred(ns, alias, domain, owner, name)
    if token == "" { return nil, fmt.Errorf("no token for alias=%s domain=%s; provide via OOB or token endpoint", in.Account.Alias, in.Account.Domain) }
    host := domain
    if host == "" { host = "github.com" }
    remoteURL := fmt.Sprintf("https://%s/%s/%s.git", host, owner, name)
    // token may be PAT or "username:password"
    user := "x-access-token"
    pass := token
    if i := strings.IndexByte(token, ':'); i > 0 {
        user = token[:i]
        pass = token[i+1:]
    }
    auth := &gitHttp.BasicAuth{Username: user, Password: pass}

    dest := in.DestDir
    if dest == "" {
        base := fmt.Sprintf("gh_%s_%s", sanitize(owner), sanitize(name))
        parent := s.storageDir
        if parent == "" { parent = os.TempDir() }
        if err := os.MkdirAll(parent, 0o700); err != nil { return nil, err }
        dest = filepath.Join(parent, base)
    }

    // Determine if we need to clone or open.
    wasCloned := false
    var repo *git.Repository
    if fi, err := os.Stat(dest); err != nil || !fi.IsDir() {
        // Fresh clone
        cloneOpts := &git.CloneOptions{URL: remoteURL, Auth: auth}
        if in.Depth > 0 { d := in.Depth; cloneOpts.Depth = d }
        if in.Branch != "" { cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(in.Branch) }
        r, err := git.PlainCloneContext(ctx, dest, cloneOpts)
        if err != nil { return nil, err }
        repo = r
        wasCloned = true
    } else {
        // Open existing repo and pull
        r, err := git.PlainOpen(dest)
        if err != nil { return nil, err }
        repo = r
        wt, err := repo.Worktree()
        if err != nil { return nil, fmt.Errorf("failed to get worktree, %v", err) }
        pullOpts := &git.PullOptions{RemoteName: "origin", Auth: auth}
        if in.Depth > 0 { pullOpts.Depth = in.Depth }
        if in.Branch != "" { pullOpts.ReferenceName = plumbing.NewBranchReferenceName(in.Branch) }
        if err := wt.Pull(pullOpts); err != nil {
            if err != git.NoErrAlreadyUpToDate && !isFastForwardUpdateError(err) {
                return nil, err
            }
        }
    }

    // Optional checkout of a specific commit.
    checkedOut := "HEAD"
    if in.Commit != "" {
        wt, err := repo.Worktree()
        if err != nil { return nil, fmt.Errorf("failed to get worktree, %v", err) }
        if err := wt.Checkout(&git.CheckoutOptions{Hash: plumbing.NewHash(in.Commit), Force: true}); err != nil { return nil, err }
        checkedOut = in.Commit
    } else if in.Branch != "" {
        checkedOut = in.Branch
    }

    return &CheckoutRepoOutput{Path: dest, CheckedOut: checkedOut, WasCloned: wasCloned}, nil
}

func sanitize(s string) string {
    return strings.NewReplacer("/", "_", ":", "_", "\\", "_", " ", "_").Replace(s)
}

func isFastForwardUpdateError(err error) bool {
    if err == nil { return false }
    // go-git does not expose a typed error for non-fast-forward; check message substring conservatively.
    return strings.Contains(err.Error(), "non-fast-forward")
}
