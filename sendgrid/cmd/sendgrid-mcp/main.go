package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/viant/mcp-protocol/authorization"
	oauthmeta "github.com/viant/mcp-protocol/oauth2/meta"
	"github.com/viant/mcp-protocol/schema"
	sendgridauth "github.com/viant/mcp-toolbox/sendgrid/auth"
	sendgridmcp "github.com/viant/mcp-toolbox/sendgrid/mcp"
	sendgridsvc "github.com/viant/mcp-toolbox/sendgrid/service"
	mcpsrv "github.com/viant/mcp/server"
	serverauth "github.com/viant/mcp/server/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/flow"
	"github.com/viant/scy/cred"
)

const (
	// sendGridMaxRequestBodyBytes accommodates the base64 and JSON envelope for
	// SendGrid's 21,000,000-byte decoded attachment limit while bounding reads.
	sendGridMaxRequestBodyBytes = int64(32 << 20)
	sendGridReadHeaderTimeout   = 10 * time.Second
	sendGridReadTimeout         = 60 * time.Second
	sendGridIdleTimeout         = 120 * time.Second
)

// Options defines CLI flags for the independent SendGrid MCP server.
type Options struct {
	HTTPAddr                string `short:"a" long:"addr" description:"HTTP listen address (empty disables HTTP)"`
	APIKeyRef               string `long:"api-key-ref" description:"Encrypted scy resource for the SendGrid API key (<source>|<kms-key>)"`
	Oauth2Config            string `short:"o" long:"oauth2config" description:"Path to JSON OAuth2 configuration (scy EncodedResource)"`
	UseIdToken              bool   `short:"i" long:"use-id-token" description:"Use ID token instead of access token for identity scoping"`
	JWTIssuer               string `long:"jwt-issuer" description:"Expected ID-token issuer; defaults to OIDC discovery"`
	JWTJWKSURL              string `long:"jwt-jwks-url" description:"Trusted JWKS URL; defaults to OIDC discovery"`
	JWTAudience             string `long:"jwt-audience" description:"Expected ID-token audience; defaults to OAuth client ID"`
	JWTAlgorithms           string `long:"jwt-algorithms" description:"Comma-separated allowed ID-token signing algorithms" default:"RS256"`
	Region                  string `long:"region" description:"SendGrid data residency region: global or eu"`
	ScratchpadRootURI       string `long:"scratchpad-root-uri" description:"Per-user scratchpad root URI template"`
	AttachmentSourceSchemes string `long:"attachment-source-schemes" description:"Comma-separated allowed attachment sourceURL schemes; empty denies sourceURL attachments"`
	ScratchpadTargetSchemes string `long:"scratchpad-target-schemes" description:"Comma-separated allowed underlying scratchpad artifact schemes; required when scratchpad is enabled"`
	NamespaceClaimKeys      string `long:"namespace-claim-keys" description:"Comma-separated identity claim lookup order (default: email,sub)"`
	MaxConcurrentSends      int    `long:"max-concurrent-sends" description:"Maximum concurrent resolve/build/send operations" default:"4"`
	SendTimeout             string `long:"send-timeout" description:"Timeout covering queueing, attachments, and provider request" default:"60s"`
}

func main() {
	ctx := context.Background()
	var opts Options
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		os.Exit(2)
	}
	applyOptionDefaults(&opts)
	if err := validateAuthMode(opts); err != nil {
		log.Fatal(err)
	}
	cfg, err := serviceConfigFromOptions(opts)
	if err != nil {
		log.Fatal(err)
	}
	service, err := sendgridsvc.NewService(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}

	options := []mcpsrv.Option{
		mcpsrv.WithImplementation(schema.Implementation{Name: "sendgrid-mcp", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(sendgridmcp.NewHandler(service, &sendgridmcp.Config{
			NamespaceClaimKeys: sendgridmcp.ParseNamespaceClaimKeys(opts.NamespaceClaimKeys),
		})),
		mcpsrv.WithEndpointAddress(opts.HTTPAddr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithStreamableURI("/mcp"),
	}

	if value := strings.TrimSpace(opts.Oauth2Config); value != "" {
		resource := scy.EncodedResource(value).Decode(context.Background(), cred.Oauth2Config{})
		secret, err := scy.New().Load(context.Background(), resource)
		if err != nil {
			log.Fatalf("failed to load oauth2config: %v", err)
		}
		oauthConfig, ok := secret.Target.(*cred.Oauth2Config)
		if !ok {
			log.Fatal("invalid oauth2config secret type")
		}
		policy := &authorization.Policy{
			Global: &authorization.Authorization{
				UseIdToken: opts.UseIdToken,
				ProtectedResourceMetadata: &oauthmeta.ProtectedResourceMetadata{
					AuthorizationServers: []string{oauthConfig.Config.Endpoint.AuthURL},
				},
			},
			ExcludeURI: "/sse,/ui/interaction/",
		}
		bff := &serverauth.BackendForFrontend{
			Client:                      &oauthConfig.Config,
			AuthorizationExchangeHeader: flow.AuthorizationExchangeHeader,
		}
		authService, err := serverauth.New(&serverauth.Config{Policy: policy, BackendForFrontend: bff})
		if err != nil {
			log.Fatalf("failed to initialize MCP auth service: %v", err)
		}
		audience := strings.TrimSpace(opts.JWTAudience)
		if audience == "" {
			audience = strings.TrimSpace(oauthConfig.Config.ClientID)
		}
		tokenVerifier, err := sendgridauth.NewOIDCVerifier(context.Background(), sendgridauth.OIDCConfig{
			AuthURL:    oauthConfig.Config.Endpoint.AuthURL,
			TokenURL:   oauthConfig.Config.Endpoint.TokenURL,
			Issuer:     opts.JWTIssuer,
			JWKSURL:    opts.JWTJWKSURL,
			Audience:   audience,
			Algorithms: splitCSV(opts.JWTAlgorithms),
		})
		if err != nil {
			log.Fatalf("failed to initialize strict OIDC verifier: %v", err)
		}
		options = append(options,
			mcpsrv.WithAuthorizer(verifiedOAuthMiddleware(authService.Middleware, tokenVerifier)),
			mcpsrv.WithProtectedResourcesHandler(authService.ProtectedResourcesHandler),
		)
	}

	server, err := mcpsrv.New(options...)
	if err != nil {
		log.Fatal(err)
	}
	if opts.HTTPAddr != "" {
		server.UseStreamableHTTP(true)
		httpServer := hardenSendGridHTTPServer(server.HTTP(context.Background(), opts.HTTPAddr))
		if err := httpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}
}

func hardenSendGridHTTPServer(server *http.Server) *http.Server {
	handler := server.Handler
	if handler == nil {
		handler = http.DefaultServeMux
	}
	server.Handler = sendGridRequestBodyLimit(handler)
	server.ReadHeaderTimeout = sendGridReadHeaderTimeout
	server.ReadTimeout = sendGridReadTimeout
	server.IdleTimeout = sendGridIdleTimeout
	return server
}

func sendGridRequestBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.ContentLength > sendGridMaxRequestBodyBytes {
			http.Error(response, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		if request.Body != nil {
			request.Body = http.MaxBytesReader(response, request.Body, sendGridMaxRequestBodyBytes)
		}
		next.ServeHTTP(response, request)
	})
}

func verifiedOAuthMiddleware(
	oauthMiddleware func(http.Handler) http.Handler,
	verifier sendgridauth.TokenVerifier,
) func(http.Handler) http.Handler {
	strictBearer := sendgridauth.VerifiedBearerMiddleware(verifier)
	return func(next http.Handler) http.Handler {
		return oauthMiddleware(strictBearer(next))
	}
}

func applyOptionDefaults(opts *Options) {
	opts.HTTPAddr = strings.TrimSpace(opts.HTTPAddr)
	opts.APIKeyRef = strings.TrimSpace(opts.APIKeyRef)
	opts.Oauth2Config = strings.TrimSpace(opts.Oauth2Config)
	opts.JWTIssuer = strings.TrimSpace(opts.JWTIssuer)
	opts.JWTJWKSURL = strings.TrimSpace(opts.JWTJWKSURL)
	opts.JWTAudience = strings.TrimSpace(opts.JWTAudience)
	opts.JWTAlgorithms = strings.TrimSpace(opts.JWTAlgorithms)
	opts.Region = strings.TrimSpace(opts.Region)
	if opts.Region == "" {
		opts.Region = sendgridsvc.DefaultRegion
	}
}

func serviceConfigFromOptions(opts Options) (sendgridsvc.Config, error) {
	timeout, err := time.ParseDuration(strings.TrimSpace(opts.SendTimeout))
	if err != nil {
		return sendgridsvc.Config{}, fmt.Errorf("invalid --send-timeout %q: %w", opts.SendTimeout, err)
	}
	return sendgridsvc.Config{
		APIKeyRef:               scy.EncodedResource(opts.APIKeyRef),
		Region:                  opts.Region,
		ScratchpadRootURI:       expandHome(opts.ScratchpadRootURI),
		AttachmentSourceSchemes: splitCSV(opts.AttachmentSourceSchemes),
		ScratchpadTargetSchemes: splitCSV(opts.ScratchpadTargetSchemes),
		MaxConcurrentSends:      opts.MaxConcurrentSends,
		SendTimeout:             timeout,
	}, nil
}

func validateAuthMode(opts Options) error {
	if strings.TrimSpace(opts.HTTPAddr) != "" && strings.TrimSpace(opts.Oauth2Config) == "" {
		return fmt.Errorf("active HTTP requires --oauth2config")
	}
	if strings.TrimSpace(opts.HTTPAddr) != "" && !opts.UseIdToken {
		return fmt.Errorf("active HTTP requires --use-id-token for verified caller identity")
	}
	return nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	seen := map[string]bool{}
	var result []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		result = append(result, part)
	}
	return result
}

func expandHome(value string) string {
	return strings.Replace(strings.TrimSpace(value), "$HOME", os.Getenv("HOME"), 1)
}
