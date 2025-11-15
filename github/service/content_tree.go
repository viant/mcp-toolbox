package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/viant/mcp-toolbox/github/adapter"
)

// ListRepoPath lists paths under the given repo path/ref. Returns repo-relative paths only.
func (s *Service) ListRepoPath(ctx context.Context, in *ListRepoInput, prompt func(string)) (*ListRepoOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("input is nil")
	}
	t := GitTarget{URL: in.URL, Account: in.Account, Repo: in.Repo, Ref: in.Ref}
	domain, owner, name, ref, _, err := t.Init(s)
	if err != nil {
		return nil, err
	}
	alias, aerr := t.GetAlias(ctx, s)
	if aerr != nil {
		return nil, aerr
	}
	return withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (*ListRepoOutput, error) {
		// Normalize empty ref to default branch
		ref = s.effectiveRef(ctx, domain, owner, name, ref, token)
		if in.Recursive {
			// Validate user-supplied ref; if invalid switch to default
			cli := adapter.New(domain)
			if strings.TrimSpace(t.Ref) != "" {
				if err := cli.ValidateRef(ctx, token, owner, name, ref); err != nil {
					if def, derr := cli.GetRepoDefaultBranch(ctx, token, owner, name); derr == nil && def != "" {
						ref = def
					}
				}
			}
			treeSha, err := cli.GetCommitTreeSHA(ctx, token, owner, name, ref)
			if err != nil {
				// Fallback to contents-based DFS over directories
				walker := s.makeContentAPI(domain)
				startPath := strings.Trim(strings.TrimPrefix(in.Path, "/"), "/")
				var out ListRepoOutput
				var stack = []string{startPath}
				visited := map[string]bool{}
				for len(stack) > 0 {
					n := len(stack) - 1
					dir := stack[n]
					stack = stack[:n]
					if visited[dir] {
						continue
					}
					visited[dir] = true
					items, werr := walker.ListContents(ctx, token, owner, name, dir, ref)
					if werr != nil {
						if def, derr := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name); derr == nil {
							items, werr = walker.ListContents(ctx, token, owner, name, dir, def)
							if werr == nil {
								ref = def
							}
						}
					}
					if werr != nil {
						return nil, werr
					}
					for _, it := range items {
						if it.Type == "dir" {
							stack = append(stack, strings.Trim(strings.TrimPrefix(it.Path, "/"), "/"))
						}
						if !passIncludeExclude(it.Path, in.Include, in.Exclude) {
							continue
						}
						out.Paths = append(out.Paths, it.Path)
					}
				}
				out.Ref = ref
				return &out, nil
			}
			// Use Trees API + per-repo cache
			startPath := strings.TrimPrefix(in.Path, "/")
			prefix := strings.Trim(startPath, "/")
			var entries []adapter.TreeEntry
			useCache := true
			cacheKey := ""
			if useCache {
				nsCache, _ := s.auth.Namespace(ctx)
				if nsCache == "" {
					nsCache = "default"
				}
				cacheKey = s.repoKey(nsCache, domain, owner, name)
				s.treeMu.RLock()
				cached, ok := s.treeCache[cacheKey]
				s.treeMu.RUnlock()
				if ok {
					if time.Now().Before(cached.expireAt) && len(cached.entries) > 0 {
						entries = cached.entries
					} else {
						s.treeMu.Lock()
						delete(s.treeCache, cacheKey)
						s.treeMu.Unlock()
					}
				}
			}
			if entries == nil {
				fetched, truncated, err := cli.GetTreeRecursive(ctx, token, owner, name, treeSha)
				if err != nil {
					return nil, err
				}
				if truncated {
					return nil, fmt.Errorf("tree listing truncated by API; narrow path or use non-recursive mode")
				}
				entries = fetched
				if useCache {
					s.treeMu.Lock()
					s.treeCache[cacheKey] = treeCacheEntry{entries: append([]adapter.TreeEntry(nil), entries...), expireAt: time.Now().Add(30 * time.Minute)}
					s.treeMu.Unlock()
				}
			}
			include := in.Include
			exclude := in.Exclude
			var collected []string
			for _, e := range entries {
				if prefix != "" && !strings.HasPrefix(e.Path, prefix+"/") && e.Path != prefix {
					continue
				}
				if !passIncludeExclude(e.Path, include, exclude) {
					continue
				}
				typ := e.Type
				if typ == "tree" {
					typ = "dir"
				} else if typ == "blob" {
					typ = "file"
				}
				if typ == "file" {
					collected = append(collected, e.Path)
				}
			}
			return &ListRepoOutput{Ref: ref, Paths: collected}, nil
		}
		// Non-recursive: single directory via contents API
		cli := s.makeContentAPI(domain)
		startPath := strings.TrimPrefix(in.Path, "/")
		useRef := s.effectiveRef(ctx, domain, owner, name, in.Ref, token)
		items, err := cli.ListContents(ctx, token, owner, name, startPath, useRef)
		if err != nil {
			if def, derr := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name); derr == nil {
				items, err = cli.ListContents(ctx, token, owner, name, startPath, def)
			}
			if err != nil {
				return nil, err
			}
		}
		include := in.Include
		exclude := in.Exclude
		var collected []string
		for _, v := range items {
			if !passIncludeExclude(v.Path, include, exclude) {
				continue
			}
			collected = append(collected, v.Path)
		}
		return &ListRepoOutput{Ref: useRef, Paths: collected}, nil
	})
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func passIncludeExclude(path string, include, exclude []string) bool {
	for _, pat := range exclude {
		if globMatch(pat, path) || globMatch(pat, pathBase(path)) {
			return false
		}
	}
	if len(include) == 0 {
		return true
	}
	for _, pat := range include {
		if globMatch(pat, path) || globMatch(pat, pathBase(path)) {
			return true
		}
	}
	return false
}

func globMatch(pattern, name string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "**/") {
		p := strings.ReplaceAll(pattern, "**/", "")
		return simplePathMatch(p, name)
	}
	return simplePathMatch(pattern, name)
}

func simplePathMatch(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	n := strings.ToLower(name)
	if strings.HasPrefix(pattern, "*") && strings.Count(pattern, "*") == 1 && strings.HasPrefix(pattern, "*.") {
		suf := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(n, suf)
	}
	if strings.HasSuffix(pattern, "/*") {
		pre := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(n, pre+"/")
	}
	if strings.Contains(pattern, "*") {
		p := strings.ReplaceAll(pattern, "*", "")
		return strings.Contains(n, p)
	}
	return n == pattern || strings.HasSuffix(n, "/"+pattern) || strings.HasPrefix(n, pattern+"/")
}
