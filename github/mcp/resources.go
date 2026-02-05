package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/viant/jsonrpc"
	"github.com/viant/mcp-protocol/schema"
	ghservice "github.com/viant/mcp-toolbox/github/service"
	"gopkg.in/yaml.v3"
)

const (
	resourceScheme           = "github"
	defaultSnapshotName      = "_snapshot.zip"
	snapshotMimeType         = "application/zip"
	rootResourceMimeType     = "text/plain"
	defaultResourcesCacheTTL = 60 * time.Second
)

type resCacheEntry struct {
	at        time.Time
	resources []schema.Resource
}

type ResourcesConfig struct {
	Auto        *bool             `json:"auto,omitempty" yaml:"auto,omitempty"`
	Account     ghservice.Account `json:"account,omitempty" yaml:"account,omitempty"`
	Visibility  string            `json:"visibility,omitempty" yaml:"visibility,omitempty"`
	Affiliation string            `json:"affiliation,omitempty" yaml:"affiliation,omitempty"`
	PerPage     int               `json:"perPage,omitempty" yaml:"perPage,omitempty"`
	Include     []string          `json:"include,omitempty" yaml:"include,omitempty"`
	Exclude     []string          `json:"exclude,omitempty" yaml:"exclude,omitempty"`
}

func LoadResourcesConfig(path string) (*ResourcesConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ResourcesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func resourcePrompt(h *Handler) func(string) {
	if h == nil || h.ops == nil || !h.ops.Implements(schema.MethodElicitationCreate) {
		return nil
	}
	return func(msg string) {
		u := extractURL(msg)
		code := extractCode(msg)
		text := buildPromptMessage(u, code)
		elicitID := newUUID()
		go func() {
			ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, _ = h.ops.Elicit(ctx2, &jsonrpc.TypedRequest[*schema.ElicitRequest]{Request: &schema.ElicitRequest{
				Params: schema.ElicitRequestParams{ElicitationId: elicitID, Message: text, Mode: schema.ElicitRequestParamsModeUrl, Url: u},
			}})
		}()
	}
}

func (h *Handler) ListResources(ctx context.Context, request *jsonrpc.TypedRequest[*schema.ListResourcesRequest]) (*schema.ListResourcesResult, *jsonrpc.Error) {
	out, _ := h.DefaultHandler.ListResources(ctx, request)
	if out == nil {
		out = &schema.ListResourcesResult{}
	}
	dyn, err := h.dynamicResources(ctx)
	if err != nil {
		return nil, jsonrpc.NewInternalError(err.Error(), nil)
	}
	seen := map[string]bool{}
	var combined []schema.Resource
	for _, r := range out.Resources {
		if r.Uri == "" || seen[r.Uri] {
			continue
		}
		seen[r.Uri] = true
		combined = append(combined, r)
	}
	for _, r := range dyn {
		if r.Uri == "" || seen[r.Uri] {
			continue
		}
		seen[r.Uri] = true
		combined = append(combined, r)
	}
	out.Resources = combined
	return out, nil
}

func (h *Handler) ReadResource(ctx context.Context, request *jsonrpc.TypedRequest[*schema.ReadResourceRequest]) (*schema.ReadResourceResult, *jsonrpc.Error) {
	if request == nil || request.Request == nil {
		return nil, jsonrpc.NewInvalidParamsError("read resource: nil request", nil)
	}
	uri := request.Request.Params.Uri
	domain, owner, repo, relPath, ok := parseResourceURI(uri)
	if !ok {
		return h.DefaultHandler.ReadResource(ctx, request)
	}
	if owner == "" {
		return nil, jsonrpc.NewInvalidParamsError("read resource: missing owner", nil)
	}
	if !isAllowedRepo(h.resources, owner, repo) {
		return nil, jsonrpc.NewInvalidParamsError("read resource: repo not allowed", nil)
	}
	if repo == "" {
		return ownerRootResult(uri, domain, owner), nil
	}
	if relPath == "" || relPath == "/" {
		return repoRootResult(uri, domain, owner, repo), nil
	}
	relPath = strings.TrimPrefix(relPath, "/")
	if relPath == defaultSnapshotName {
		return h.readSnapshotResource(ctx, uri, domain, owner, repo)
	}
	return h.readRepoFileResource(ctx, uri, domain, owner, repo, relPath)
}

func (h *Handler) dynamicResources(ctx context.Context) ([]schema.Resource, error) {
	cfg := h.resources
	auto := true
	if cfg != nil && cfg.Auto != nil {
		auto = *cfg.Auto
	}
	var resources []schema.Resource
	needsListing := true
	if cfg != nil && len(cfg.Include) > 0 {
		explicit, needsList := explicitResources(cfg)
		if len(explicit) > 0 {
			resources = append(resources, explicit...)
		}
		needsListing = needsList
		if !needsListing {
			return resources, nil
		}
		if !auto && len(cfg.Include) == 0 {
			return resources, nil
		}
	} else if !auto {
		return resources, nil
	}
	ctxNS, svc, rerr := h.resolveService(ctx)
	if rerr != nil {
		return nil, rerr
	}
	account := ghservice.Account{Alias: "default", Domain: "github.com"}
	visibility := ""
	affiliation := ""
	perPage := 0
	if cfg != nil {
		if strings.TrimSpace(cfg.Account.Alias) != "" {
			account.Alias = cfg.Account.Alias
		}
		if strings.TrimSpace(cfg.Account.Domain) != "" {
			account.Domain = cfg.Account.Domain
		}
		visibility = strings.TrimSpace(cfg.Visibility)
		affiliation = strings.TrimSpace(cfg.Affiliation)
		perPage = cfg.PerPage
	}
	cacheKey := h.resourcesCacheKey(h.cacheNamespace(ctx), account, visibility, affiliation, perPage, cfg, auto)
	if cached, ok := h.resourcesCacheGet(cacheKey); ok {
		return cached, nil
	}
	var repos []ghservice.Repo
	if cfg != nil && len(cfg.Include) > 0 {
		owners, needUserList := includeOwnersForListing(cfg.Include)
		for _, owner := range owners {
			out, err := svc.ListOwnerRepos(ctxNS, &ghservice.ListOwnerReposInput{
				Account: account,
				Owner:   owner,
				PerPage: perPage,
			}, resourcePrompt(h))
			if err != nil {
				return resources, err
			}
			repos = append(repos, out.Repos...)
		}
		if needUserList || len(owners) == 0 {
			repoOut, err := svc.ListRepos(ctxNS, &ghservice.ListReposInput{
				Account:     account,
				Visibility:  visibility,
				Affiliation: affiliation,
				PerPage:     perPage,
			}, resourcePrompt(h))
			if err != nil {
				return resources, err
			}
			repos = append(repos, repoOut.Repos...)
		}
	} else {
		repoOut, err := svc.ListRepos(ctxNS, &ghservice.ListReposInput{
			Account:     account,
			Visibility:  visibility,
			Affiliation: affiliation,
			PerPage:     perPage,
		}, resourcePrompt(h))
		if err != nil {
			return resources, err
		}
		repos = append(repos, repoOut.Repos...)
	}
	repos = uniqueRepos(repos)
	owners := map[string]bool{}
	for _, repo := range repos {
		owner, name := splitFullName(repo.FullName, repo.Name)
		if owner == "" || name == "" {
			continue
		}
		if !isAllowedRepo(cfg, owner, name) {
			continue
		}
		if !owners[owner] {
			owners[owner] = true
			resources = append(resources, ownerResourceEntry(account.Domain, owner))
		}
		resources = append(resources, rootResourceEntry(account.Domain, owner, name))
		resources = append(resources, snapshotResourceEntry(account.Domain, owner, name))
	}
	populateSnapshotSizes(resources, svc)
	h.resourcesCachePut(cacheKey, resources)
	return resources, nil
}

func explicitResources(cfg *ResourcesConfig) ([]schema.Resource, bool) {
	if cfg == nil || len(cfg.Include) == 0 {
		return nil, true
	}
	needsListing := false
	owners := map[string]bool{}
	var resources []schema.Resource
	settings := repoSettingsFor(cfg)
	for _, entry := range cfg.Include {
		value := strings.TrimSpace(entry)
		if value == "" {
			continue
		}
		if hasWildcard(value) {
			needsListing = true
			continue
		}
		owner, repo := splitFullName(value, "")
		if owner == "" || repo == "" {
			needsListing = true
			continue
		}
		if !isAllowedRepo(cfg, owner, repo) {
			continue
		}
		if !owners[owner] {
			owners[owner] = true
			resources = append(resources, ownerResourceEntry(settings.Domain, owner))
		}
		resources = append(resources, rootResourceEntry(settings.Domain, owner, repo))
		resources = append(resources, snapshotResourceEntry(settings.Domain, owner, repo))
	}
	return resources, needsListing
}

func hasWildcard(value string) bool {
	return strings.ContainsAny(value, "*?[")
}

func includeOwnersForListing(include []string) ([]string, bool) {
	seen := map[string]bool{}
	var owners []string
	needUserList := false
	for _, entry := range include {
		o, r := splitOwnerRepoPattern(entry)
		if o == "" || hasGlob(o) {
			needUserList = true
			continue
		}
		if r == "" || hasGlob(r) {
			key := strings.ToLower(strings.TrimSpace(o))
			if key != "" && !seen[key] {
				seen[key] = true
				owners = append(owners, strings.TrimSpace(o))
			}
		}
	}
	return owners, needUserList
}

func uniqueRepos(repos []ghservice.Repo) []ghservice.Repo {
	seen := map[string]bool{}
	var out []ghservice.Repo
	for _, repo := range repos {
		key := strings.ToLower(strings.TrimSpace(repo.FullName))
		if key == "" {
			key = strings.ToLower(strings.TrimSpace(repo.Name))
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, repo)
	}
	return out
}

func ownerResourceEntry(domain, owner string) schema.Resource {
	uri := strings.TrimRight(formatResourceURI(domain, owner, "", ""), "/") + "/"
	return schema.Resource{
		Name:     owner,
		Uri:      uri,
		MimeType: ptr(rootResourceMimeType),
		Meta: map[string]any{
			"root": true,
			"kind": "owner",
		},
	}
}

func rootResourceEntry(domain, owner, repo string) schema.Resource {
	return schema.Resource{
		Name:     owner + "/" + repo,
		Uri:      strings.TrimRight(formatResourceURI(domain, owner, repo, ""), "/") + "/",
		MimeType: ptr(rootResourceMimeType),
		Meta: map[string]any{
			"root": true,
			"kind": "repo",
		},
	}
}

func snapshotResourceEntry(domain, owner, repo string) schema.Resource {
	return schema.Resource{
		Name:     owner + "/" + repo + " snapshot",
		Uri:      formatResourceURI(domain, owner, repo, defaultSnapshotName),
		MimeType: ptr(snapshotMimeType),
		Meta: map[string]any{
			"kind": "snapshot",
		},
	}
}

func populateSnapshotSizes(resources []schema.Resource, svc *ghservice.Service) {
	if svc == nil || len(resources) == 0 {
		return
	}
	for i := range resources {
		r := &resources[i]
		if r == nil || r.Size != nil {
			continue
		}
		if r.Meta == nil || r.Meta["kind"] != "snapshot" {
			continue
		}
		domain, owner, repo, _, ok := parseResourceURI(r.Uri)
		if !ok || owner == "" || repo == "" {
			continue
		}
		if size, ok := svc.SnapshotCachedSize(domain, owner, repo); ok && size > 0 {
			v := int(size)
			r.Size = &v
		}
	}
}

func ownerRootResult(uri, domain, owner string) *schema.ReadResourceResult {
	elem := schema.ReadResourceResultContentsElem{Uri: uri, Text: fmt.Sprintf("github owner root %s", owner)}
	meta := map[string]any{
		"owner": owner,
		"root":  true,
		"kind":  "owner",
	}
	if domain != "" {
		meta["domain"] = domain
	}
	return &schema.ReadResourceResult{
		Contents: []schema.ReadResourceResultContentsElem{elem},
		Meta:     meta,
	}
}

func repoRootResult(uri, domain, owner, repo string) *schema.ReadResourceResult {
	elem := schema.ReadResourceResultContentsElem{Uri: uri, Text: fmt.Sprintf("github repo root %s/%s", owner, repo)}
	meta := map[string]any{
		"owner": owner,
		"repo":  repo,
		"root":  true,
		"kind":  "repo",
	}
	if domain != "" {
		meta["domain"] = domain
	}
	return &schema.ReadResourceResult{
		Contents: []schema.ReadResourceResultContentsElem{elem},
		Meta:     meta,
	}
}

func (h *Handler) readSnapshotResource(ctx context.Context, uri, domain, owner, repo string) (*schema.ReadResourceResult, *jsonrpc.Error) {
	cfg := h.resources
	settings := repoSettingsFor(cfg)
	domainEff := settings.Domain
	if strings.TrimSpace(domain) != "" {
		domainEff = domain
	}
	ctxNS, svc, rerr := h.resolveService(ctx)
	if rerr != nil {
		return nil, jsonrpc.NewInternalError("resolve namespace: "+rerr.Error(), nil)
	}
	out, err := svc.ReadRepoSnapshot(ctxNS, &ghservice.SnapshotInput{
		GitTarget: ghservice.GitTarget{
			Account: ghservice.Account{
				Alias:  settings.Alias,
				Domain: domainEff,
			},
			Repo: ghservice.RepoRef{
				Owner: owner,
				Name:  repo,
			},
		},
	}, resourcePrompt(h))
	if err != nil {
		return nil, jsonrpc.NewInternalError(err.Error(), nil)
	}
	elem := schema.ReadResourceResultContentsElem{
		Uri:      uri,
		MimeType: ptr(snapshotMimeType),
		Blob:     base64.StdEncoding.EncodeToString(out.Data),
	}
	meta := map[string]any{
		"owner":      owner,
		"repo":       repo,
		"ref":        out.Ref,
		"sha":        out.SHA,
		"md5":        out.MD5,
		"size":       out.Size,
		"cached":     out.FromCache,
		"snapshotAt": out.Timestamp.UTC().Format(time.RFC3339),
		"kind":       "snapshot",
	}
	if domainEff != "" {
		meta["domain"] = domainEff
	}
	return &schema.ReadResourceResult{Contents: []schema.ReadResourceResultContentsElem{elem}, Meta: meta}, nil
}

func (h *Handler) readRepoFileResource(ctx context.Context, uri, domain, owner, repo, relPath string) (*schema.ReadResourceResult, *jsonrpc.Error) {
	cfg := h.resources
	settings := repoSettingsFor(cfg)
	domainEff := settings.Domain
	if strings.TrimSpace(domain) != "" {
		domainEff = domain
	}
	ctxNS, svc, rerr := h.resolveService(ctx)
	if rerr != nil {
		return nil, jsonrpc.NewInternalError("resolve namespace: "+rerr.Error(), nil)
	}
	out, err := svc.ReadRepoFile(ctxNS, &ghservice.ReadInput{
		GitTarget: ghservice.GitTarget{
			Account: ghservice.Account{
				Alias:  settings.Alias,
				Domain: domainEff,
			},
			Repo: ghservice.RepoRef{
				Owner: owner,
				Name:  repo,
			},
		},
		Path: relPath,
	}, resourcePrompt(h))
	if err != nil {
		return nil, jsonrpc.NewInternalError(err.Error(), nil)
	}
	elem := schema.ReadResourceResultContentsElem{
		Uri: uri,
	}
	if len(out.Content) > 0 {
		elem.Blob = base64.StdEncoding.EncodeToString(out.Content)
		elem.MimeType = ptr(detectMime(relPath))
	} else {
		elem.Text = out.Text
		elem.MimeType = ptr(detectMime(relPath))
	}
	meta := map[string]any{
		"owner": owner,
		"repo":  repo,
		"path":  relPath,
		"kind":  "file",
	}
	if domainEff != "" {
		meta["domain"] = domainEff
	}
	return &schema.ReadResourceResult{Contents: []schema.ReadResourceResultContentsElem{elem}, Meta: meta}, nil
}

func detectMime(rel string) string {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".md":
		return "text/markdown"
	case ".txt":
		return "text/plain"
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "text/yaml"
	case ".go":
		return "text/x-go"
	case ".py":
		return "text/x-python"
	default:
		return "application/octet-stream"
	}
}

func parseResourceURI(uri string) (domain, owner, repo, relPath string, ok bool) {
	parsed, err := url.Parse(uri)
	if err != nil || strings.ToLower(parsed.Scheme) != resourceScheme {
		return "", "", "", "", false
	}
	host := strings.TrimSpace(parsed.Host)
	rel := strings.TrimPrefix(parsed.Path, "/")
	if rel == "" {
		return "", host, "", "", true
	}
	parts := strings.SplitN(rel, "/", 3)
	if host != "" && strings.Contains(host, ".") {
		domain = host
		if len(parts) >= 1 {
			owner = parts[0]
		}
		if len(parts) >= 2 {
			repo = parts[1]
		}
		if len(parts) == 3 {
			relPath = parts[2]
		}
	} else {
		owner = host
		if len(parts) >= 1 {
			repo = parts[0]
		}
		if len(parts) == 2 {
			relPath = parts[1]
		}
	}
	if repo == "" {
		return domain, owner, "", "", true
	}
	if parsed.RawQuery != "" {
		if relPath == "" {
			relPath = "?" + parsed.RawQuery
		} else {
			relPath += "?" + parsed.RawQuery
		}
	}
	return domain, owner, repo, relPath, true
}

func formatResourceURI(domain, owner, repo, relPath string) string {
	host := strings.TrimSpace(owner)
	if strings.TrimSpace(domain) != "" {
		host = strings.TrimSpace(domain)
	}
	path := ""
	if strings.TrimSpace(domain) != "" && owner != "" {
		path = "/" + owner
	}
	if repo != "" {
		path += "/" + repo
	}
	if relPath != "" {
		path += "/" + relPath
	}
	return fmt.Sprintf("%s://%s%s", resourceScheme, host, path)
}

type repoSettings struct {
	Alias  string
	Domain string
}

func repoSettingsFor(cfg *ResourcesConfig) repoSettings {
	if cfg == nil {
		return repoSettings{}
	}
	settings := repoSettings{}
	if strings.TrimSpace(cfg.Account.Alias) != "" {
		settings.Alias = cfg.Account.Alias
	}
	if strings.TrimSpace(cfg.Account.Domain) != "" {
		settings.Domain = cfg.Account.Domain
	}
	return settings
}

func splitFullName(full, fallback string) (owner, repo string) {
	if strings.TrimSpace(full) == "" {
		return "", ""
	}
	parts := strings.SplitN(full, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if fallback != "" {
		return parts[0], fallback
	}
	return "", ""
}

func isAllowedRepo(cfg *ResourcesConfig, owner, repo string) bool {
	if cfg == nil {
		return true
	}
	if len(cfg.Include) > 0 && !matchesAnyPattern(cfg.Include, owner, repo) {
		return false
	}
	if len(cfg.Exclude) > 0 && matchesAnyPattern(cfg.Exclude, owner, repo) {
		return false
	}
	return true
}

func matchesAnyPattern(patterns []string, owner, repo string) bool {
	for _, p := range patterns {
		o, r := splitOwnerRepoPattern(p)
		if o == "" && r == "" {
			continue
		}
		if o != "" && !globMatch(o, owner) {
			continue
		}
		if r != "" && !globMatch(r, repo) {
			continue
		}
		return true
	}
	return false
}

func splitOwnerRepoPattern(pattern string) (string, string) {
	p := strings.TrimSpace(pattern)
	if p == "" {
		return "", ""
	}
	if strings.Contains(p, "/") {
		parts := strings.SplitN(p, "/", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return p, ""
}

func globMatch(pattern, value string) bool {
	if pattern == "" {
		return true
	}
	if !hasGlob(pattern) {
		return strings.EqualFold(pattern, value)
	}
	pat := strings.ToLower(pattern)
	val := strings.ToLower(value)
	ok, _ := path.Match(pat, val)
	return ok
}

func hasGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

func ptrOrNil(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	v := strings.TrimSpace(s)
	return &v
}

func ptr[T any](v T) *T {
	return &v
}

func (h *Handler) cacheNamespace(ctx context.Context) string {
	if h == nil || h.nsProvider == nil {
		return "default"
	}
	desc, _ := h.nsProvider.Namespace(ctx)
	if desc.Name == "" {
		return "default"
	}
	return desc.Name
}

func (h *Handler) resourcesCacheKey(ns string, account ghservice.Account, visibility, affiliation string, perPage int, cfg *ResourcesConfig, auto bool) string {
	var include []string
	var exclude []string
	if cfg != nil {
		include = cfg.Include
		exclude = cfg.Exclude
	}
	return fmt.Sprintf(
		"ns=%s|alias=%s|domain=%s|vis=%s|aff=%s|perPage=%d|auto=%t|include=%s|exclude=%s",
		ns,
		strings.TrimSpace(account.Alias),
		strings.TrimSpace(account.Domain),
		strings.TrimSpace(visibility),
		strings.TrimSpace(affiliation),
		perPage,
		auto,
		strings.Join(include, ","),
		strings.Join(exclude, ","),
	)
}

func (h *Handler) resourcesCacheGet(key string) ([]schema.Resource, bool) {
	if h == nil || h.resTTL <= 0 {
		return nil, false
	}
	h.resMu.RLock()
	entry, ok := h.resCache[key]
	h.resMu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Since(entry.at) > h.resTTL {
		h.resMu.Lock()
		delete(h.resCache, key)
		h.resMu.Unlock()
		return nil, false
	}
	return copyResources(entry.resources), true
}

func (h *Handler) resourcesCachePut(key string, resources []schema.Resource) {
	if h == nil || h.resTTL <= 0 {
		return
	}
	h.resMu.Lock()
	h.resCache[key] = resCacheEntry{at: time.Now(), resources: copyResources(resources)}
	h.resMu.Unlock()
}

func copyResources(in []schema.Resource) []schema.Resource {
	if len(in) == 0 {
		return nil
	}
	out := make([]schema.Resource, len(in))
	copy(out, in)
	return out
}
