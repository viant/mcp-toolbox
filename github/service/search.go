package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/viant/mcp-toolbox/github/adapter"
)

// SearchRepoContent searches files and returns previews (with optional content-based matches), no apply.
func (s *Service) SearchRepoContent(ctx context.Context, in *FindFilesPreviewInput, prompt func(string)) (*FindFilesPreviewOutput, error) {
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

	return withRepoCredentialRetry(ctx, s, alias, domain, owner, name, prompt, func(token string) (*FindFilesPreviewOutput, error) {
		includeQs := filterContentPatterns(in.Queries)
		excludeQs := filterContentPatterns(in.ExcludeQueries)
		ci := in.CaseInsensitive
		if len(includeQs) > 0 && !ci {
			ci = true
		}
		skipBinary := in.SkipBinary
		maxSize := in.MaxSize
		if maxSize <= 0 {
			maxSize = 5 * 1024 * 1024
		}
		previewMode := strings.ToLower(strings.TrimSpace(in.Mode))
		previewBytes := in.Bytes
		if previewBytes <= 0 {
			previewBytes = 1024
		}
		maxFiles := in.MaxFiles
		if maxFiles <= 0 {
			maxFiles = 200
		}
		snippetLines := in.Lines
		if snippetLines <= 0 {
			snippetLines = 1
		}
		maxSnippetsPerFile := in.MaxBlocks
		if maxSnippetsPerFile <= 0 {
			maxSnippetsPerFile = 5
		}

		out := &FindFilesPreviewOutput{Stats: PreviewStats{}}
		// Resolve ref if empty to default branch
		ref = s.effectiveRef(ctx, domain, owner, name, ref, token)

		ns := s.Namespace(ctx)
		zPath, _, _, shaKey, zerr := s.GetOrFetchSnapshotZip(ctx, ns, alias, domain, owner, name, ref, token)
		usedRef := strings.TrimSpace(ref)
		if zerr != nil {
			// Fallback to default branch snapshot if specific ref failed
			def, derr := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name)
			if derr == nil && def != "" && strings.TrimSpace(ref) != "" && strings.TrimSpace(ref) != def {
				if z2, _, _, sha2, zerr2 := s.GetOrFetchSnapshotZip(ctx, ns, alias, domain, owner, name, def, token); zerr2 == nil {
					zPath = z2
					shaKey = sha2
					usedRef = def
				} else {
					return nil, zerr
				}
			} else {
				return nil, zerr
			}
		}
		out.Sha = shaKey
		out.Ref = usedRef

		// Build candidate file list using Trees API if available, else contents DFS
		cli := adapter.New(domain)
		resolvedRef := ref
		if strings.TrimSpace(resolvedRef) == "" {
			if def, derr := (&GitTarget{Ref: ""}).ResolveRef(ctx, cli, token, owner, name, ""); derr == nil && def != "" {
				resolvedRef = def
			}
		}
		var entries []adapter.TreeEntry
		if shaTree, e1 := cli.GetCommitTreeSHA(ctx, token, owner, name, resolvedRef); e1 == nil {
			if ents, _, e2 := cli.GetTreeRecursive(ctx, token, owner, name, shaTree); e2 == nil {
				entries = ents
			}
		}
		if len(entries) == 0 {
			if def, derr := cli.GetRepoDefaultBranch(ctx, token, owner, name); derr == nil && def != "" {
				if sha2, e3 := cli.GetCommitTreeSHA(ctx, token, owner, name, def); e3 == nil {
					if ents2, _, e4 := cli.GetTreeRecursive(ctx, token, owner, name, sha2); e4 == nil {
						entries = ents2
						resolvedRef = def
					}
				}
			}
		}
		prefix := strings.Trim(strings.TrimPrefix(in.Path, "/"), "/")
		include := in.Include
		exclude := in.Exclude
		type collectedItem struct {
			Path string
			Size int
			Sha  string
		}
		var collected []collectedItem
		if len(entries) == 0 {
			walker := s.makeContentAPI(domain)
			var stack = []string{prefix}
			visited := map[string]bool{}
			for len(stack) > 0 {
				n := len(stack) - 1
				dir := stack[n]
				stack = stack[:n]
				if visited[dir] {
					continue
				}
				visited[dir] = true
				items, werr := walker.ListContents(ctx, token, owner, name, dir, resolvedRef)
				if werr != nil {
					if def, derr := adapter.New(domain).GetRepoDefaultBranch(ctx, token, owner, name); derr == nil {
						items, werr = walker.ListContents(ctx, token, owner, name, dir, def)
						if werr == nil {
							resolvedRef = def
						}
					}
				}
				if werr != nil {
					break
				}
				for _, it := range items {
					if it.Type == "dir" {
						stack = append(stack, strings.Trim(strings.TrimPrefix(it.Path, "/"), "/"))
					}
					if it.Type == "file" {
						if !passIncludeExclude(it.Path, include, exclude) {
							continue
						}
						collected = append(collected, collectedItem{Path: it.Path, Size: it.Size, Sha: it.Sha})
					}
				}
			}
		} else {
			for _, e := range entries {
				if prefix != "" && !strings.HasPrefix(e.Path, prefix+"/") && e.Path != prefix {
					continue
				}
				if !passIncludeExclude(e.Path, include, exclude) {
					continue
				}
				if e.Type != "blob" {
					continue
				}
				collected = append(collected, collectedItem{Path: e.Path, Size: e.Size, Sha: e.Sha})
			}
		}

		// Filter by content queries if provided
		matchedPaths := map[string]bool{}
		if len(includeQs) > 0 || len(excludeQs) > 0 {
			cand := make(map[string]bool, len(collected))
			for _, it := range collected {
				cand[it.Path] = true
			}
			if data, ok := s.GetSnapshotBytes(domain, owner, name, shaKey); ok {
				inc, exc := s.buildContentSetsFromBytes(data, cand, includeQs, excludeQs, skipBinary, int64(maxSize), ci)
				for p := range cand {
					if exc != nil && exc[p] {
						continue
					}
					if inc == nil || inc[p] {
						matchedPaths[p] = true
					}
				}
			} else {
				inc, exc := s.buildContentSets(zPath, cand, includeQs, excludeQs, skipBinary, int64(maxSize), ci)
				for p := range cand {
					if exc != nil && exc[p] {
						continue
					}
					if inc == nil || inc[p] {
						matchedPaths[p] = true
					}
				}
			}
		} else {
			for _, it := range collected {
				matchedPaths[it.Path] = true
			}
		}

		files := make([]PreviewFile, 0, minInt(maxFiles, len(matchedPaths)))
		filesScanned := len(collected)
		filesMatched := 0
		for _, it := range collected {
			if !matchedPaths[it.Path] {
				continue
			}
			filesMatched++
			if len(files) >= maxFiles {
				break
			}
			var content []byte
			if data, ok := s.GetSnapshotBytes(domain, owner, name, shaKey); ok {
				if b, rerr := readZipEntryFromBytes(data, it.Path, int64(maxSize)); rerr == nil {
					content = b
				}
			} else {
				if b, rerr := readZipEntry(zPath, it.Path, int64(maxSize)); rerr == nil {
					content = b
				}
			}
			if skipBinary && !isProbablyText(content) {
				continue
			}
			pv := PreviewFile{Path: it.Path}
			pv.Matches = countMatches(content, includeQs, ci)
			// Decide preview mode
			mode := previewMode
			if mode != "matches" && mode != "head" {
				if len(includeQs) > 0 || len(excludeQs) > 0 {
					mode = "matches"
				} else {
					mode = "head"
				}
			}
			effMode := mode
			if mode == "matches" && len(includeQs) == 0 && len(excludeQs) == 0 {
				effMode = "head"
			}
			if effMode == "matches" {
				snips, _, coveredMatches, totalMatches := buildMatchSnippetsCompact(content, includeQs, ci, snippetLines, previewBytes, maxSnippetsPerFile)
				pv.Snippets = snips
				if totalMatches > coveredMatches {
					pv.Omitted = totalMatches - coveredMatches
				}
			} else {
				if previewBytes > 0 {
					head := content
					cut := false
					if len(head) > previewBytes {
						head = head[:previewBytes]
						cut = true
					}
					pv.Snippets = []PreviewSnippet{{Start: 1, End: 1, Text: string(head), Cut: cut}}
				}
			}
			files = append(files, pv)
		}
		out.Files = files
		out.Stats = PreviewStats{Scanned: filesScanned, Matched: filesMatched, Truncated: filesMatched > maxFiles}
		return out, nil
	})
}
