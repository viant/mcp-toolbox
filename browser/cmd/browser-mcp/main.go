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
	bmcp "github.com/viant/mcp-toolbox/browser/mcp"
	browsersvc "github.com/viant/mcp-toolbox/browser/service"
	mcpsrv "github.com/viant/mcp/server"
)

type Options struct {
	HTTPAddr            string `short:"a" long:"addr" description:"HTTP listen address (default: 127.0.0.1:5002; set to 'disabled' to skip HTTP server)"`
	UseData             bool   `long:"use-data" description:"Return tool results in structured content instead of text field"`
	InstallDir          string `long:"install-dir" description:"Directory for auto-downloaded drivers (default: uses /opt/local/webdriver if it already has drivers, else $HOME/.mcp-toolbox/browser/webdriver)"`
	Headful             bool   `long:"headful" description:"Force non-headless mode (removes headless args from capabilities)"`
	MatchChromeDriver   bool   `long:"match-chrome-driver" description:"Best-effort detect installed Chrome/Chromium major version and download/update matching Chrome-for-Testing chromedriver"`
	NoMatchChromeDriver bool   `long:"no-match-chrome-driver" description:"Disable Chrome/Chromium auto-detection for chromedriver downloads"`
}

func main() {
	// Default match-chrome-driver to true; user can disable with --no-match-chrome-driver.
	opts := Options{MatchChromeDriver: true, HTTPAddr: "127.0.0.1:5002"}
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		// Print helpful error instead of silent exit; allow --help to exit 0.
		if ferr, ok := err.(*flags.Error); ok && ferr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		log.Printf("flag parse error: %v", err)
		os.Exit(2)
	}

	svc := browsersvc.NewService(&browsersvc.Config{
		UseData:               opts.UseData,
		InstallDir:            opts.InstallDir,
		ForceHeadful:          opts.Headful,
		AutoMatchChromeDriver: opts.MatchChromeDriver && !opts.NoMatchChromeDriver,
	})

	// Perform chromedriver auto-match at startup in the current environment
	// (best-effort) so users can see the match outcome immediately.
	if opts.MatchChromeDriver && !opts.NoMatchChromeDriver {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if out, err := svc.DriverInstall(ctx, &browsersvc.DriverInstallInput{}); err != nil {
			log.Printf("chromedriver match at startup: %v", err)
		} else if out != nil {
			msg := "chromedriver match at startup: prepared chromedriver"
			if out.Version != "" {
				msg += " " + out.Version
			}
			if out.DriverPath != "" {
				msg += " at " + out.DriverPath
			}
			log.Printf("%s", msg)
		}
	}
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

	if opts.HTTPAddr == "disabled" {
		log.Printf("browser-mcp HTTP server disabled")
		return
	}

	server.UseStreamableHTTP(true)
	srv := server.HTTP(context.Background(), opts.HTTPAddr)
	srv.ReadHeaderTimeout = 10 * time.Second
	srv.ReadTimeout = 60 * time.Second
	srv.WriteTimeout = 60 * time.Second
	srv.IdleTimeout = 120 * time.Second

	log.Printf("browser-mcp listening on %s", srv.Addr)

	// Run HTTP server and wait for shutdown signal.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Listen for SIGINT/SIGTERM.
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
	log.Printf("browser-mcp stopped")
}
