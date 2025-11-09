package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This test exercises the GitHub Enterprise repo using real network + token.
// It runs only with: go test -tags local ./github/service -run Test_E2E_GHE
// Repo under test: https://github.vianttech.com/adelphic/mediator
func Test_E2E_GHE_List_Download_And_Optional_Checkout(t *testing.T) {
	storage := t.TempDir()
	// Start HTTP server with built-in endpoints so user can feed token or start device flow (if clientID is set).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())
	svc := NewService(&Config{ClientID: "", StorageDir: storage, CallbackBaseURL: baseURL})
	mux := http.NewServeMux()
	svc.RegisterHTTP(mux)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	alias := "viant"
	domain := "github.vianttech.com"
	// Provide a single OOB URL that contains a unified form for token/basic and device flow.
	oobURL := fmt.Sprintf("%s/github/auth/oob?alias=%s&domain=%s", baseURL, alias, domain)
	t.Logf("Open OOB URL to provide credentials: %s", oobURL)

	// Wait up to 3m for token to be present if not already.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for svc.loadToken("default", alias, domain) == "" {
		select {
		case <-ctx.Done():
			t.Skip("No token provided/ingested; skipping E2E")
		case <-time.After(2 * time.Second):
		}
	}

	fmt.Println("ListRepoPath ....")
	// 1) List root path
	lst, err := svc.ListRepoPath(ctx, &ListRepoInput{
		GitTarget: GitTarget{Account: Account{Alias: alias, Domain: domain}, Repo: RepoRef{Owner: "adelphic", Name: "mediator"}, Ref: ""},
		Path:      "/common/params",
		Recursive: true,
	}, nil)
	if err != nil {
		t.Fatalf("list path error: %v", err)
	}

	for _, item := range lst.Items {
		fmt.Println(item.Name, item.Path, item.Type, item.Size)
	}
	content, err := svc.DownloadRepoFile(ctx, &DownloadInput{GitTarget: GitTarget{
		URL: "github.vianttech.com/adelphic/mediator",
		Ref: "main",
	},
		Path: "common/params/price.go",
	}, nil)
	if err != nil {
		t.Fatalf("list path error: %v", err)
	}

	fmt.Println("ListRepoPath done ", string(content.Content), err)

	if len(lst.Items) == 0 {
		t.Fatalf("expected non-empty repo root listing")
	}

	// Find a file to download
	filePath := ""
	for _, it := range lst.Items {
		if it.Type == "file" {
			filePath = it.Path
			break
		}
	}
	if filePath == "" {
		t.Skip("no file found at repo root to download")
	}

	// 2) Download that file
	got, err := svc.DownloadRepoFile(ctx, &DownloadInput{
		GitTarget: GitTarget{Account: Account{Alias: alias, Domain: domain}, Repo: RepoRef{Owner: "adelphic", Name: "mediator"}},
		Path:      filePath,
	}, nil)
	if err != nil {
		t.Fatalf("download error: %v", err)
	}
	if len(got.Content) == 0 {
		t.Fatalf("downloaded empty content for %s", filePath)
	}

	// 3) Optionally perform a shallow clone if git is available
	if _, err := exec.LookPath("git"); err == nil {
		dest := filepath.Join(svc.storageDir, "e2e_checkout")
		out, err := svc.CheckoutRepo(ctx, &CheckoutRepoInput{
			GitTarget: GitTarget{Account: Account{Alias: alias, Domain: domain}, Repo: RepoRef{Owner: "adelphic", Name: "mediator"}},
			Depth:     1,
			DestDir:   dest,
		}, nil)
		if err != nil {
			t.Fatalf("checkout error: %v", err)
		}
		if out.Path != dest {
			t.Fatalf("unexpected checkout path: %s", out.Path)
		}
		if _, err := os.Stat(dest); err != nil {
			t.Fatalf("expected checkout directory to exist: %v", err)
		}
	} else {
		t.Log("git not found in PATH; skipping checkout step")
	}
}

func Test_E2E_GHE_SearchPrice(t *testing.T) {
	// Enable verbose service logs and cap token wait to ease troubleshooting
	_ = os.Setenv("GITHUB_MCP_DEBUG", "1")
	_ = os.Setenv("GITHUB_MCP_WAIT_SECS", "300")

	storage := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())
	svc := NewService(&Config{ClientID: "", StorageDir: storage, CallbackBaseURL: baseURL})
	mux := http.NewServeMux()
	svc.RegisterHTTP(mux)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	alias := "viant"
	domain := "github.vianttech.com"

	// Provide OOB page link (includes repo hint) so a user can paste a token
	oobURL := fmt.Sprintf("%s/github/auth/oob?alias=%s&domain=%s&url=%s/viant/mdp", baseURL, alias, domain, domain)
	t.Logf("Open OOB URL to provide credentials: %s", oobURL)

	// Wait for a token (or skip after timeout to avoid hanging CI)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for svc.loadToken("default", alias, domain) == "" {
		select {
		case <-ctx.Done():
			t.Skip("No token provided/ingested; skipping E2E")
		case <-time.After(2 * time.Second):
		}
	}

	start := time.Now()
	in := &ListRepoInput{
		GitTarget:          GitTarget{URL: domain + "/viant/mdp"},
		Path:               "/",
		Recursive:          true,
		FindInFilesInclude: []string{"price"},
		Concurrency:        8,
		Include:            []string{"**/*.go", "**/*.md"},
		Exclude:            []string{"**/*_test.go", "**/vendor/**"},
	}
	t.Logf("Listing with params: %+v", in)
	out, err := svc.ListRepoPath(ctx, in, func(msg string) { t.Logf("PROMPT: %s", msg) })
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ListRepoPath error after %s: %v", elapsed, err)
	}
	t.Logf("ListRepoPath returned %d items in %s", len(out.Items), elapsed)
	// Print first few results for inspection
	max := 20
	for i, it := range out.Items {
		if i >= max {
			break
		}
		t.Logf("%s\t%s\t%s\t%d", it.Type, it.Path, it.Name, it.Size)
	}
}

// Run only with: go test -tags local ./github/service -run Test_E2E_GHE_ListRepoFiles_MDP -v
// Mirrors the provided listRepoFiles request against GHE: github.vianttech.com/viant/mdp
func Test_E2E_GHE_ListRepoFiles_MDP(t *testing.T) {
	// Optional: turn on verbose logs and extend wait
	_ = os.Setenv("GITHUB_MCP_DEBUG", "1")
	_ = os.Setenv("GITHUB_MCP_WAIT_SECS", "300")

	storage := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen error: %v", err)
	}
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())
	svc := NewService(&Config{ClientID: "", StorageDir: storage, CallbackBaseURL: baseURL})
	mux := http.NewServeMux()
	svc.RegisterHTTP(mux)
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()

	alias := "viant"
	domain := "github.vianttech.com"

	// Provide OOB page link so a user can paste a token for this domain/repo
	oobURL := fmt.Sprintf("%s/github/auth/oob?alias=%s&domain=%s&url=%s/viant/mdp", baseURL, alias, domain, domain)
	t.Logf("Open OOB URL to provide credentials: %s", oobURL)

	// Wait for a token (or skip after timeout to avoid hanging CI)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for svc.loadToken("default", alias, domain) == "" {
		select {
		case <-ctx.Done():
			t.Skip("No token provided/ingested; skipping E2E")
		case <-time.After(2 * time.Second):
		}
	}

	// Use the exact request parameters supplied
	start := time.Now()
	in := &ListRepoInput{
		GitTarget:   GitTarget{URL: domain + "/viant/mdp"},
		Path:        "/",
		Recursive:   true,
		Concurrency: 8,
		Include:     []string{"**/*.go", "**/*.sql", "**/*.yaml", "**/*.yml", "**/*.md"},
		Exclude:     []string{"**/*_test.go", "**/vendor/**", ".git/**"},
	}
	t.Logf("Listing with params: %+v", in)
	out, err := svc.ListRepoPath(ctx, in, func(msg string) { t.Logf("PROMPT: %s", msg) })
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ListRepoPath error after %s: %v", elapsed, err)
	}
	in.Path = "model"
	out, err = svc.ListRepoPath(ctx, in, func(msg string) { t.Logf("PROMPT: %s", msg) })

	t.Logf("ListRepoPath returned %d items in %s", len(out.Items), elapsed)
	// Print first few results for inspection
	max := 20
	for i, it := range out.Items {
		if i >= max {
			break
		}
		t.Logf("%s\t%s\t%s\t%d", it.Type, it.Path, it.Name, it.Size)
	}
}
