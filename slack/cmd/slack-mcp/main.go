package main

import (
	"context"
	"log"
	"os"

	flags "github.com/jessevdk/go-flags"
	"github.com/viant/mcp-protocol/schema"
	slmcp "github.com/viant/mcp-toolbox/slack/mcp"
	slservice "github.com/viant/mcp-toolbox/slack/service"
	mcpsrv "github.com/viant/mcp/server"
	"github.com/viant/scy"
)

// Options defines CLI flags for the Slack MCP server.
type Options struct {
	HTTPAddr    string `short:"a" long:"addr" description:"HTTP listen address (empty disables HTTP)"`
	SecretsBase string `long:"secretsBase" description:"AFS/scy base URL for persisting tokens (e.g., mem://localhost/mcp-slack)"`
	TokenRef    string `long:"token-ref" description:"scy EncodedResource for a Slack bot token (plain string or {token:\"...\"})"`
	UseData     bool   `long:"use-data" description:"Return tool results in structured content instead of text field"`
}

func main() {
	var opts Options
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		os.Exit(2)
	}
	if opts.SecretsBase == "" {
		opts.SecretsBase = "mem://localhost/mcp-slack"
	}
	cfg := &slservice.Config{SecretsBase: opts.SecretsBase, TokenRef: scy.EncodedResource(opts.TokenRef), UseData: opts.UseData}
	svc := slservice.NewService(cfg)

	server, err := mcpsrv.New(
		mcpsrv.WithImplementation(schema.Implementation{Name: "slack-mcp", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(slmcp.NewHandler(svc)),
		mcpsrv.WithEndpointAddress(opts.HTTPAddr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithStreamableURI("/mcp"),
	)
	if err != nil {
		log.Fatal(err)
	}
	if opts.HTTPAddr != "" {
		server.UseStreamableHTTP(true)
		if err := server.HTTP(context.Background(), opts.HTTPAddr).ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}
}
