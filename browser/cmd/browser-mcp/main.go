package main

import (
	"context"
	"log"
	"os"

	flags "github.com/jessevdk/go-flags"
	"github.com/viant/mcp-protocol/schema"
	bmcp "github.com/viant/mcp-toolbox/browser/mcp"
	browsersvc "github.com/viant/mcp-toolbox/browser/service"
	mcpsrv "github.com/viant/mcp/server"
)

type Options struct {
	HTTPAddr   string `short:"a" long:"addr" description:"HTTP listen address (empty disables HTTP)"`
	UseData    bool   `long:"use-data" description:"Return tool results in structured content instead of text field"`
	InstallDir string `long:"install-dir" description:"Directory for auto-downloaded drivers (default: uses /opt/local/webdriver if it already has drivers, else $HOME/.mcp-toolbox/browser/webdriver)"`
	Headful    bool   `long:"headful" description:"Force non-headless mode (removes headless args from capabilities)"`
}

func main() {
	var opts Options
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		os.Exit(2)
	}

	svc := browsersvc.NewService(&browsersvc.Config{UseData: opts.UseData, InstallDir: opts.InstallDir, ForceHeadful: opts.Headful})
	server, err := mcpsrv.New(
		mcpsrv.WithImplementation(schema.Implementation{Name: "browser-mcp", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(bmcp.NewHandler(svc)),
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
