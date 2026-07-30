package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
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
	sendGridServiceName = "sendgrid-mcp"
	sendGridVersion     = "0.1.0"
	sendGridEndpoint    = "/mcp"

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
	opts, failure := parseCommandLine(os.Args[1:], os.Stdout)
	if failure != nil {
		logStartupFailure(log.Default(), failure)
		os.Exit(2)
	}
	if opts == nil {
		return
	}
	if failure := run(ctx, *opts, log.Default()); failure != nil {
		logStartupFailure(log.Default(), failure)
		os.Exit(1)
	}
}

func parseCommandLine(args []string, helpOutput io.Writer) (*Options, *startupFailure) {
	var opts Options
	parser := flags.NewParser(&opts, flags.Default&^flags.PrintErrors)
	if _, err := parser.ParseArgs(args); err != nil {
		if flags.WroteHelp(err) {
			parser.WriteHelp(helpOutput)
			return nil, nil
		}
		return nil, &startupFailure{
			stage: startupStageConfig,
			err:   errors.New("invalid command-line configuration"),
		}
	}
	return &opts, nil
}

type startupStage string

const (
	startupStageConfig   startupStage = "config"
	startupStageSendGrid startupStage = "sendgrid"
	startupStageOAuth    startupStage = "oauth"
	startupStageOIDC     startupStage = "oidc"
	startupStageServer   startupStage = "server"
	startupStageListener startupStage = "listener"
	startupStageServe    startupStage = "serve"
)

type startupFailure struct {
	stage startupStage
	err   error
}

func (f *startupFailure) Error() string {
	if f == nil || f.err == nil {
		return ""
	}
	return f.err.Error()
}

func (f *startupFailure) Unwrap() error {
	if f == nil {
		return nil
	}
	return f.err
}

func logStartupFailure(logger *log.Logger, failure *startupFailure) {
	logger.Printf(
		"startup_failed service=%q version=%q stage=%s error=%q",
		sendGridServiceName,
		sendGridVersion,
		failure.stage,
		failure.Error(),
	)
}

type startupDependencies struct {
	newSendGridService func(context.Context, sendgridsvc.Config) (*sendgridsvc.Service, error)
	loadOAuthConfig    func(context.Context, string) (*cred.Oauth2Config, error)
	newAuthService     func(*serverauth.Config) (*serverauth.Service, error)
	newOIDCVerifier    func(context.Context, sendgridauth.OIDCConfig) (sendgridauth.TokenVerifier, error)
	newMCPServer       func(...mcpsrv.Option) (*mcpsrv.Server, error)
	listen             func(string, string) (net.Listener, error)
	serve              func(*http.Server, net.Listener) error
}

func defaultStartupDependencies() startupDependencies {
	return startupDependencies{
		newSendGridService: func(ctx context.Context, cfg sendgridsvc.Config) (*sendgridsvc.Service, error) {
			return sendgridsvc.NewService(ctx, cfg)
		},
		loadOAuthConfig: loadOAuthConfig,
		newAuthService:  serverauth.New,
		newOIDCVerifier: func(ctx context.Context, cfg sendgridauth.OIDCConfig) (sendgridauth.TokenVerifier, error) {
			return sendgridauth.NewOIDCVerifier(ctx, cfg)
		},
		newMCPServer: mcpsrv.New,
		listen:       net.Listen,
		serve: func(server *http.Server, listener net.Listener) error {
			return server.Serve(listener)
		},
	}
}

func run(ctx context.Context, opts Options, logger *log.Logger) *startupFailure {
	return runWithDependencies(ctx, opts, logger, defaultStartupDependencies())
}

func runWithDependencies(ctx context.Context, opts Options, logger *log.Logger, deps startupDependencies) *startupFailure {
	applyOptionDefaults(&opts)
	if err := validateAuthMode(opts); err != nil {
		return &startupFailure{stage: startupStageConfig, err: err}
	}
	cfg, err := serviceConfigFromOptions(opts)
	if err != nil {
		return &startupFailure{stage: startupStageConfig, err: errors.New("invalid SendGrid service configuration")}
	}
	namespaceKeys := sendgridmcp.ParseNamespaceClaimKeys(opts.NamespaceClaimKeys)

	service, err := deps.newSendGridService(ctx, cfg)
	if err != nil {
		return &startupFailure{stage: startupStageSendGrid, err: errors.New("failed to initialize SendGrid service")}
	}
	logStartupConfig(logger, opts, cfg, namespaceKeys)

	options := []mcpsrv.Option{
		mcpsrv.WithImplementation(schema.Implementation{Name: sendGridServiceName, Version: sendGridVersion}),
		mcpsrv.WithNewHandler(sendgridmcp.NewHandler(service, &sendgridmcp.Config{
			NamespaceClaimKeys: namespaceKeys,
		})),
		mcpsrv.WithEndpointAddress(opts.HTTPAddr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithStreamableURI(sendGridEndpoint),
	}

	if value := strings.TrimSpace(opts.Oauth2Config); value != "" {
		oauthConfig, err := deps.loadOAuthConfig(ctx, value)
		if err != nil || oauthConfig == nil {
			return &startupFailure{stage: startupStageOAuth, err: errors.New("failed to load OAuth configuration")}
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
		authService, err := deps.newAuthService(&serverauth.Config{Policy: policy, BackendForFrontend: bff})
		if err != nil || authService == nil {
			return &startupFailure{stage: startupStageOAuth, err: errors.New("failed to initialize OAuth service")}
		}
		audience := strings.TrimSpace(opts.JWTAudience)
		if audience == "" {
			audience = strings.TrimSpace(oauthConfig.Config.ClientID)
		}
		tokenVerifier, err := deps.newOIDCVerifier(ctx, sendgridauth.OIDCConfig{
			AuthURL:    oauthConfig.Config.Endpoint.AuthURL,
			TokenURL:   oauthConfig.Config.Endpoint.TokenURL,
			Issuer:     opts.JWTIssuer,
			JWKSURL:    opts.JWTJWKSURL,
			Audience:   audience,
			Algorithms: splitCSV(opts.JWTAlgorithms),
		})
		if err != nil {
			return &startupFailure{stage: startupStageOIDC, err: errors.New("failed to initialize OIDC verifier")}
		}
		options = append(options,
			mcpsrv.WithAuthorizer(verifiedOAuthMiddleware(authService.Middleware, tokenVerifier)),
			mcpsrv.WithProtectedResourcesHandler(authService.ProtectedResourcesHandler),
		)
	}

	server, err := deps.newMCPServer(options...)
	if err != nil {
		return &startupFailure{stage: startupStageServer, err: fmt.Errorf("failed to initialize MCP server: %w", err)}
	}
	if opts.HTTPAddr != "" {
		server.UseStreamableHTTP(true)
		httpServer := hardenSendGridHTTPServer(server.HTTP(ctx, opts.HTTPAddr))
		return serveHTTPServer(logger, httpServer, deps)
	}
	return nil
}

func loadOAuthConfig(ctx context.Context, value string) (*cred.Oauth2Config, error) {
	resource := scy.EncodedResource(value).Decode(ctx, cred.Oauth2Config{})
	secret, err := scy.New().Load(ctx, resource)
	if err != nil || secret == nil {
		return nil, errors.New("OAuth secret load failed")
	}
	oauthConfig, ok := secret.Target.(*cred.Oauth2Config)
	if !ok {
		return nil, errors.New("OAuth secret has invalid type")
	}
	return oauthConfig, nil
}

func logStartupConfig(logger *log.Logger, opts Options, cfg sendgridsvc.Config, namespaceKeys []string) {
	scratchpadEnabled := strings.TrimSpace(cfg.ScratchpadRootURI) != ""
	scratchpadScheme := ""
	sourceSchemes := ""
	targetSchemes := ""
	namespaceClaimKeys := ""
	if scratchpadEnabled {
		scratchpadScheme = configuredURIScheme(cfg.ScratchpadRootURI)
		sourceSchemes = strings.Join(cfg.AttachmentSourceSchemes, ",")
		targetSchemes = strings.Join(cfg.ScratchpadTargetSchemes, ",")
		namespaceClaimKeys = strings.Join(namespaceKeys, ",")
	}
	logger.Printf(
		"startup_config service=%q version=%q listen_addr=%q endpoint=%q region=%q",
		sendGridServiceName,
		sendGridVersion,
		opts.HTTPAddr,
		sendGridEndpoint,
		cfg.Region,
	)
	logger.Printf(
		"startup_auth enabled=%t use_id_token=%t",
		strings.TrimSpace(opts.Oauth2Config) != "",
		opts.UseIdToken,
	)
	logger.Printf(
		"startup_scratchpad enabled=%t scheme=%q source_schemes=%q target_schemes=%q namespace_claim_keys=%q",
		scratchpadEnabled,
		scratchpadScheme,
		sourceSchemes,
		targetSchemes,
		namespaceClaimKeys,
	)
	logger.Printf(
		"startup_limits max_concurrent_sends=%d send_timeout=%q",
		cfg.MaxConcurrentSends,
		cfg.SendTimeout.String(),
	)
}

func configuredURIScheme(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Scheme)
}

func serveHTTPServer(logger *log.Logger, httpServer *http.Server, deps startupDependencies) *startupFailure {
	listener, err := deps.listen("tcp", httpServer.Addr)
	if err != nil {
		return &startupFailure{stage: startupStageListener, err: fmt.Errorf("failed to bind HTTP listener: %w", err)}
	}
	defer listener.Close()

	logger.Printf(
		"startup_ready service=%q version=%q listen_addr=%q endpoint=%q",
		sendGridServiceName,
		sendGridVersion,
		listener.Addr().String(),
		sendGridEndpoint,
	)
	if err := deps.serve(httpServer, listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return &startupFailure{stage: startupStageServe, err: fmt.Errorf("HTTP server failed: %w", err)}
	}
	return nil
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
	opts.Region = strings.ToLower(strings.TrimSpace(opts.Region))
	if opts.Region == "" {
		opts.Region = sendgridsvc.DefaultRegion
	}
	opts.ScratchpadRootURI = strings.TrimSpace(opts.ScratchpadRootURI)
	opts.AttachmentSourceSchemes = strings.TrimSpace(opts.AttachmentSourceSchemes)
	opts.ScratchpadTargetSchemes = strings.TrimSpace(opts.ScratchpadTargetSchemes)
	opts.NamespaceClaimKeys = strings.TrimSpace(opts.NamespaceClaimKeys)
	opts.SendTimeout = strings.TrimSpace(opts.SendTimeout)
	if opts.MaxConcurrentSends == 0 {
		opts.MaxConcurrentSends = sendgridsvc.DefaultMaxConcurrentSends
	}
	if opts.SendTimeout == "" {
		opts.SendTimeout = sendgridsvc.DefaultSendTimeout.String()
	}
}

func serviceConfigFromOptions(opts Options) (sendgridsvc.Config, error) {
	timeout, err := time.ParseDuration(strings.TrimSpace(opts.SendTimeout))
	if err != nil {
		return sendgridsvc.Config{}, fmt.Errorf("invalid --send-timeout %q: %w", opts.SendTimeout, err)
	}
	if timeout == 0 {
		timeout = sendgridsvc.DefaultSendTimeout
	}
	return sendgridsvc.Config{
		APIKeyRef:               scy.EncodedResource(opts.APIKeyRef),
		Region:                  strings.ToLower(strings.TrimSpace(opts.Region)),
		ScratchpadRootURI:       expandHome(opts.ScratchpadRootURI),
		AttachmentSourceSchemes: splitLowerCSV(opts.AttachmentSourceSchemes),
		ScratchpadTargetSchemes: splitLowerCSV(opts.ScratchpadTargetSchemes),
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

func splitLowerCSV(value string) []string {
	values := splitCSV(value)
	for index := range values {
		values[index] = strings.ToLower(values[index])
	}
	return splitCSV(strings.Join(values, ","))
}

func expandHome(value string) string {
	return strings.Replace(strings.TrimSpace(value), "$HOME", os.Getenv("HOME"), 1)
}
