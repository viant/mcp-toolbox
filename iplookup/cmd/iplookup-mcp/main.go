package main

import (
	"context"
	"log"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/viant/mcp-protocol/schema"
	ipmcp "github.com/viant/mcp-toolbox/iplookup/mcp"
	"github.com/viant/mcp-toolbox/iplookup/service"
	mcpsrv "github.com/viant/mcp/server"
)

type Options struct {
	HTTPAddr string `short:"a" long:"addr" description:"HTTP listen address (default: 127.0.0.1:5090; set to 'disabled' to skip HTTP server)"`
}

func main() {
	opts := Options{HTTPAddr: "127.0.0.1:5090"}
	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := service.LoadConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}

	svc, err := service.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = svc.Close() }()

	server, err := mcpsrv.New(
		mcpsrv.WithImplementation(schema.Implementation{Name: "iplookup-mcp", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(ipmcp.NewHandler(svc)),
		mcpsrv.WithEndpointAddress(opts.HTTPAddr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithStreamableURI("/mcp"),
	)
	if err != nil {
		log.Fatal(err)
	}

	if opts.HTTPAddr == "disabled" {
		log.Printf("iplookup-mcp HTTP server disabled")
		return
	}

	server.UseStreamableHTTP(true)
	srv := server.HTTP(context.Background(), opts.HTTPAddr)
	srv.ReadHeaderTimeout = 10 * time.Second
	log.Printf("iplookup-mcp listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
