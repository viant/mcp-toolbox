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
	jiramcp "github.com/viant/mcp-toolbox/jira/mcp"
	jirasvc "github.com/viant/mcp-toolbox/jira/service"
	mcpsrv "github.com/viant/mcp/server"
	serverauth "github.com/viant/mcp/server/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/flow"
	"github.com/viant/scy/cred"
)

// Options defines CLI flags for the Jira MCP server.
type Options struct {
	HTTPAddr      string `short:"a" long:"addr" description:"HTTP listen address (empty disables HTTP)"`
	UseData       bool   `long:"use-data" description:"Return structured data instead of text"`
	Oauth2Config  string `short:"o" long:"oauth2config" description:"Path to JSON OAuth2 configuration file (scy EncodedResource)"`
	UseIdToken    bool   `short:"i" long:"use-id-token" description:"Use ID token (instead of access token) for identity scoping"`
	PublicBaseURL string `long:"public-base-url" description:"Public base URL for OOB/auth callbacks (e.g., http://localhost:7789)"`
}

func main() {
	var opts Options
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		os.Exit(2)
	}

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
	svc := jirasvc.NewService(&jirasvc.Config{UseData: opts.UseData, CallbackBaseURL: baseURL})

	// Build server options baseline
	options := []mcpsrv.Option{
		mcpsrv.WithImplementation(schema.Implementation{Name: "jira-mcp", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(jiramcp.NewHandler(svc)),
		mcpsrv.WithEndpointAddress(opts.HTTPAddr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithStreamableURI("/mcp"),
		mcpsrv.WithCustomHTTPHandler("/jira/auth/oob", svc.OOBHandler()),
		mcpsrv.WithCustomHTTPHandler("/jira/auth/token", svc.TokenIngestHandler()),
		mcpsrv.WithCustomHTTPHandler("/jira/auth/check", svc.TokenCheckHandler()),
		mcpsrv.WithCustomHTTPHandler("/jira/auth/verify", svc.VerifyHandler()),
	}

	// Optional server-level OAuth2
	if v := strings.TrimSpace(opts.Oauth2Config); v != "" {
		res := scy.EncodedResource(v).Decode(context.Background(), cred.Oauth2Config{})
		sec, err := scy.New().Load(context.Background(), res)
		if err != nil {
			log.Fatalf("failed to load oauth2config: %v", err)
		}
		oc, ok := sec.Target.(*cred.Oauth2Config)
		if !ok {
			log.Fatalf("invalid oauth2config secret type")
		}
		authPolicy := &authorization.Policy{
			Global: &authorization.Authorization{UseIdToken: opts.UseIdToken, ProtectedResourceMetadata: &oauthmeta.ProtectedResourceMetadata{
				AuthorizationServers: []string{oc.Config.Endpoint.AuthURL},
			}},
			// Keep SSE and elicitation UI open (sqlkit parity)
			ExcludeURI: "/sse,/ui/interaction/",
		}
		header := flow.AuthorizationExchangeHeader
		bff := &serverauth.BackendForFrontend{Client: &oc.Config, AuthorizationExchangeHeader: header}
		authSvc, err := serverauth.New(&serverauth.Config{Policy: authPolicy, BackendForFrontend: bff})
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
	return filepath.Join(dir, "secret", "mcp-jira")
}
