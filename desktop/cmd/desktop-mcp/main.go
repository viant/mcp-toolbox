package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/viant/mcp-protocol/schema"
	dmcp "github.com/viant/mcp-toolbox/desktop/mcp"
	desktopsvc "github.com/viant/mcp-toolbox/desktop/service"
	mcpsrv "github.com/viant/mcp/server"
)

type Options struct {
	HTTPAddr string `short:"a" long:"addr" description:"HTTP listen address (default: 127.0.0.1:5010; set to 'disabled' to skip HTTP server)"`
	UseData  bool   `long:"use-data" description:"Return tool results in structured content instead of text field"`
}

func main() {
	opts := Options{HTTPAddr: "127.0.0.1:5010"}
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		if ferr, ok := err.(*flags.Error); ok && ferr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		log.Printf("flag parse error: %v", err)
		os.Exit(2)
	}

	svc := desktopsvc.NewService(&desktopsvc.Config{UseData: opts.UseData})

	server, err := mcpsrv.New(
		mcpsrv.WithImplementation(schema.Implementation{Name: "desktop-mcp", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(dmcp.NewHandler(svc)),
		mcpsrv.WithEndpointAddress(opts.HTTPAddr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithStreamableURI("/mcp"),
	)
	if err != nil {
		log.Fatal(err)
	}

	if opts.HTTPAddr == "disabled" {
		log.Printf("desktop-mcp HTTP server disabled")
		return
	}

	server.UseStreamableHTTP(true)
	srv := server.HTTP(context.Background(), opts.HTTPAddr)
	srv.ReadHeaderTimeout = 10 * time.Second
	srv.ReadTimeout = 60 * time.Second
	srv.WriteTimeout = 60 * time.Second
	srv.IdleTimeout = 120 * time.Second

	log.Printf("desktop-mcp listening on %s", srv.Addr)

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("shutdown signal received: %v", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("http shutdown error: %v", err)
	}
	if err := <-errCh; err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
	log.Printf("desktop-mcp stopped")
}
