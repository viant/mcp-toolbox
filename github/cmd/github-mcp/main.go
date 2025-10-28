package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/viant/mcp-protocol/schema"
	ghmcp "github.com/viant/mcp-toolbox/github/mcp"
	ghservice "github.com/viant/mcp-toolbox/github/service"
	mcpsrv "github.com/viant/mcp/server"
)

var (
	addr     = flag.String("addr", ":7789", "HTTP listen address")
	clientID = flag.String("client-id", "", "GitHub OAuth app client ID")
	storage  = flag.String("storage", defaultStorageDir(), "Directory for auth tokens")
)

func main() {
	os.Setenv("GITHUB_MCP_DEBUG", "1")

	flag.Parse()
	// Client ID is optional; when empty, device flow won't be available. Token ingestion remains supported via HTTP.
	baseURL := "http://localhost"
	if *addr != "" {
		hostport := *addr
		if hostport[0] == ':' {
			hostport = "localhost" + hostport
		}
		baseURL = "http://" + hostport
	}
	svc := ghservice.NewService(&ghservice.Config{ClientID: *clientID, StorageDir: *storage, CallbackBaseURL: baseURL})
	server, err := mcpsrv.New(
		mcpsrv.WithImplementation(schema.Implementation{Name: "github-mcp", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(ghmcp.NewHandler(svc)),
		mcpsrv.WithEndpointAddress(*addr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithCustomHTTPHandler("/github/auth/device/", svc.DeviceHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/pending", svc.PendingListHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/pending/clear", svc.PendingClearHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/token", svc.TokenIngestHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/start", svc.DeviceStartHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/check", svc.TokenCheckHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/oob", svc.OOBHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/verify", svc.VerifyHandler()),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := server.HTTP(context.Background(), *addr).ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func defaultStorageDir() string {
	dir, _ := os.UserConfigDir()
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "secret", "mcp-github")
}
