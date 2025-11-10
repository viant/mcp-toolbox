package service

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/mcp-toolbox/github/adapter"
)

type fakeContentAPI struct {
	items []struct {
		t, name, path, sha string
		size               int
	}
	file         []byte
	unauthorized bool
}

func (f *fakeContentAPI) ListContents(_ context.Context, token, owner, name, path, ref string) ([]adapterContentItem, error) {
	if f.unauthorized {
		return nil, errUnauthorized
	}
	out := make([]adapterContentItem, 0, len(f.items))
	for _, v := range f.items {
		out = append(out, adapterContentItem{Type: v.t, Name: v.name, Path: v.path, Sha: v.sha, Size: v.size})
	}
	return out, nil
}
func (f *fakeContentAPI) GetFileContent(_ context.Context, token, owner, name, path, ref string) ([]byte, error) {
	if f.unauthorized {
		return nil, errUnauthorized
	}
	return append([]byte(nil), f.file...), nil
}

// Minimal adapter item mirror to avoid importing adapter in tests.
type adapterContentItem struct {
	Type, Name, Path, Sha string
	Size                  int
}

// Interface shape to match service.contentAPI for tests.
type contentAPITest interface {
	ListContents(ctx context.Context, token, owner, name, path, ref string) ([]adapterContentItem, error)
	GetFileContent(ctx context.Context, token, owner, name, path, ref string) ([]byte, error)
}

// Glue types to satisfy service.contentAPI without importing adapter in this test file.
var _ contentAPITest = (*fakeContentAPI)(nil)

// Use type alias to map adapter.ContentItem to our local adapterContentItem when compiling.
// We can't declare aliases across packages here, so we add thin wrappers below.

// Compile-time shims to adapt to service.contentAPI method signatures.
type contentAPIShim struct{ inner *fakeContentAPI }

func (s contentAPIShim) ListContents(ctx context.Context, token, owner, name, path, ref string) ([]adapter.ContentItem, error) {
	items, err := s.inner.ListContents(ctx, token, owner, name, path, ref)
	if err != nil {
		return nil, err
	}
	out := make([]adapter.ContentItem, 0, len(items))
	for _, v := range items {
		out = append(out, adapter.ContentItem{Type: v.Type, Name: v.Name, Path: v.Path, Sha: v.Sha, Size: v.Size})
	}
	return out, nil
}
func (s contentAPIShim) GetFileContent(ctx context.Context, token, owner, name, path, ref string) ([]byte, error) {
	return s.inner.GetFileContent(ctx, token, owner, name, path, ref)
}

var errUnauthorized = errors.New("unauthorized")

func Test_ListRepoPath_and_Download_without_clone(t *testing.T) {
	svc := newTestService(t)
	svc.saveToken("default", "acc", "", "TKN")

	fake := &fakeContentAPI{
		items: []struct {
			t, name, path, sha string
			size               int
		}{
			{t: "file", name: "README.md", path: "README.md", sha: "sha1", size: 12},
			{t: "dir", name: "cmd", path: "cmd", sha: "sha2", size: 0},
		},
		file: []byte("hello world"),
	}
	svc.makeContentAPI = func(domain string) contentAPI { return contentAPIShim{inner: fake} }

	// List path
	lst, err := svc.ListRepoPath(context.Background(), &ListRepoInput{GitTarget: GitTarget{Account: Account{Alias: "acc"}, Repo: RepoRef{Owner: "viant", Name: "mcp-toolbox"}}, Path: "/"}, nil)
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	if len(lst.Paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(lst.Paths))
	}
	if lst.Paths[0] != "README.md" || lst.Paths[1] != "cmd" {
		t.Fatalf("unexpected paths: %+v", lst.Paths)
	}

	// Download file
	got, err := svc.DownloadRepoFile(context.Background(), &DownloadInput{GitTarget: GitTarget{Account: Account{Alias: "acc"}, Repo: RepoRef{Owner: "viant", Name: "mcp-toolbox"}}, Path: "README.md"}, nil)
	if err != nil {
		t.Fatalf("download error: %v", err)
	}
	if string(got.Content) != "hello world" {
		t.Fatalf("unexpected content: %q", string(got.Content))
	}
}
