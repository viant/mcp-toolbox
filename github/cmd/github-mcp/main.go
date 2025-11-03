package main

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"github.com/viant/mcp-protocol/authorization"
	oauthmeta "github.com/viant/mcp-protocol/oauth2/meta"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/scy/auth/flow"

	ghmcp "github.com/viant/mcp-toolbox/github/mcp"
	ghservice "github.com/viant/mcp-toolbox/github/service"
	mcpsrv "github.com/viant/mcp/server"
	serverauth "github.com/viant/mcp/server/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	_ "github.com/viant/scy/kms/blowfish"
)

// Options defines CLI flags for the GitHub MCP server.
type Options struct {
	HTTPAddr      string `short:"a" long:"addr"  description:"HTTP listen address (empty disables HTTP)"`
	Storage       string `long:"storage" description:"Directory for auth tokens"`
	SecretsBase   string `long:"secretsBase" description:"AFS/scy base URL for persisting tokens (e.g., mem://localhost/mcp-github)"`
	ClientID      string `long:"client-id" description:"GitHub OAuth app client ID"`
	Oauth2Config  string `short:"o" long:"oauth2config" description:"Path to JSON OAuth2 configuration file (scy EncodedResource)"`
	UseIdToken    bool   `short:"i" long:"use-id-token" description:"Use ID token (instead of access token) for identity scoping"`
	PublicBaseURL string `long:"public-base-url" description:"Public base URL for OOB/auth callbacks (e.g., http://mcp-toolbox-github.agently.svc.cluster.local:7789)"`
}

func main() {

	// Parse CLI flags
	var opts Options
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		os.Exit(2)
	}
	if opts.SecretsBase == "" {
		opts.SecretsBase = "mem://localhost/mcp-github"
	}
	// Client ID is optional; when empty, device flow won't be available. Token ingestion remains supported via HTTP.
	baseURL := strings.TrimRight(strings.TrimSpace(opts.PublicBaseURL), "/")
	if baseURL == "" {
		baseURL = "http://localhost"
		if opts.HTTPAddr != "" {
			hostport := opts.HTTPAddr
			if hostport[0] == ':' {
				hostport = "localhost" + hostport
			}
			baseURL = "http://" + hostport
		}
	}
	svc := ghservice.NewService(&ghservice.Config{ClientID: opts.ClientID, StorageDir: opts.Storage, SecretsBase: opts.SecretsBase, CallbackBaseURL: baseURL})

	// Base server options
	options := []mcpsrv.Option{
		mcpsrv.WithImplementation(schema.Implementation{Name: "github-mcp", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(ghmcp.NewHandler(svc)),
		mcpsrv.WithEndpointAddress(opts.HTTPAddr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithStreamableURI("/mcp"),
		mcpsrv.WithCustomHTTPHandler("/github/auth/device/", svc.DeviceHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/pending", svc.PendingListHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/pending/clear", svc.PendingClearHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/token", svc.TokenIngestHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/start", svc.DeviceStartHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/check", svc.TokenCheckHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/oob", svc.OOBHandler()),
		mcpsrv.WithCustomHTTPHandler("/github/auth/verify", svc.VerifyHandler()),
	}

	// Optional: enable server-level OAuth2 via config
	if v := strings.TrimSpace(opts.Oauth2Config); v != "" {
		res := scy.EncodedResource(v).Decode(context.Background(), cred.Oauth2Config{})
		sec, err := scy.New().Load(context.Background(), res)
		if err != nil {
			log.Fatalf("failed to load oauth2config: %v", err)
		}
		oauth2Config, ok := sec.Target.(*cred.Oauth2Config)
		if !ok {
			log.Fatalf("invalid oauth2config secret type")
		}
		authPolicy := &authorization.Policy{
			Global: &authorization.Authorization{UseIdToken: opts.UseIdToken, ProtectedResourceMetadata: &oauthmeta.ProtectedResourceMetadata{
				AuthorizationServers: []string{oauth2Config.Config.Endpoint.AuthURL},
			}},
			// Match sqlkit: allow SSE/UI without auth; protect /mcp
			ExcludeURI: "/sse,/ui/interaction/",
		}

		header := flow.AuthorizationExchangeHeader
		bff := &serverauth.BackendForFrontend{Client: &oauth2Config.Config, AuthorizationExchangeHeader: header}
		authSvc, err := serverauth.New(&serverauth.Config{BackendForFrontend: bff, Policy: authPolicy})
		if err != nil {
			log.Fatalf("failed to init auth service: %v", err)
		}
		options = append(options,
			mcpsrv.WithAuthorizer(authSvc.Middleware),
			mcpsrv.WithProtectedResourcesHandler(authSvc.ProtectedResourcesHandler),
		)
	}

	server, err := mcpsrv.New(options...)
	if err != nil {
		log.Fatal(err)
	}
	if opts.HTTPAddr != "" {
		// Enable streamable HTTP so /mcp endpoint is active
		server.UseStreamableHTTP(true)
		if err := server.HTTP(context.Background(), opts.HTTPAddr).ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}
}

func defaultStorageDir() string {
	dir, _ := os.UserConfigDir()
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "secret", "mcp-github")
}
