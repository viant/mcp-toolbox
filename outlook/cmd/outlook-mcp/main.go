package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	flags "github.com/jessevdk/go-flags"
	"github.com/viant/mcp-protocol/authorization"
	oauthmeta "github.com/viant/mcp-protocol/oauth2/meta"
	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mcp-toolbox/outlook/mcp"
	mcpsrv "github.com/viant/mcp/server"
	serverauth "github.com/viant/mcp/server/auth"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/flow"
	"github.com/viant/scy/cred"
	_ "github.com/viant/scy/kms/blowfish"
)

// Options defines CLI flags for the Outlook MCP server.
type Options struct {
	HTTPAddr                string `short:"a" long:"addr" description:"HTTP listen address (empty disables HTTP)"`
	ClientID                string `long:"client-id" description:"Azure AD application (client) ID"`
	TenantID                string `long:"tenant-id" description:"Tenant ID or 'organizations'"`
	SecretsBase             string `long:"secretsBase" description:"AFS/scy base URL for persisting auth records (e.g., mem://localhost/mcp-outlook)"`
	AzureRef                string `long:"azure-ref" description:"scy EncodedResource for Azure cred (e.g., gcp://...|blowfish://default)"`
	Oauth2Config            string `short:"o" long:"oauth2config" description:"Path to JSON OAuth2 configuration file (scy EncodedResource)"`
	BFFRedirectURI          string `long:"bff-redirect-uri" description:"Redirect URI for Backend-For-Frontend OAuth flow (browser callback)"`
	UseIdToken              bool   `short:"i" long:"use-id-token" description:"Use ID token (instead of access token) for identity scoping"`
	PublicBaseURL           string `long:"public-base-url" description:"Public base URL for OOB/auth callbacks (e.g., http://mcp-toolbox-outlook.agently.svc.cluster.local:7788)"`
	ScratchpadRootURI       string `long:"scratchpad-root-uri" description:"Shared scratchpad root URI template for scratchpad:// attachments"`
	ScratchpadUserID        string `long:"scratchpad-user-id" description:"Fallback user id for local/no-auth scratchpad attachment resolution"`
	AttachmentSourceSchemes string `long:"attachment-source-schemes" description:"Comma-separated allowed attachment sourceURL schemes; empty allows all"`
	ScratchpadTargetSchemes string `long:"scratchpad-target-schemes" description:"Comma-separated allowed underlying artifact source schemes after scratchpad resolution"`
	NamespaceClaimKeys      string `long:"namespace-claim-keys" description:"Comma-separated JWT identity claim lookup order for per-user namespaces (default: email,sub)"`
}

func main() {

	var opts Options
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		os.Exit(2)
	}
	applyOptionDefaults(&opts)
	if opts.ClientID == "" && opts.AzureRef == "" {
		log.Fatal("missing --client-id/OUTLOOK_CLIENT_ID (or provide --azure-ref / OUTLOOK_AZURE_REF)")
	}
	debugf("startup options addr=%q tenant=%q client_id_set=%t azure_ref_set=%t oauth2config_set=%t public_base_url_set=%t secrets_base_set=%t scratchpad_root_set=%t scratchpad_user_id_set=%t attachment_source_schemes=%q scratchpad_target_schemes=%q namespace_claim_keys=%q",
		opts.HTTPAddr,
		opts.TenantID,
		strings.TrimSpace(opts.ClientID) != "",
		strings.TrimSpace(opts.AzureRef) != "",
		strings.TrimSpace(opts.Oauth2Config) != "",
		strings.TrimSpace(opts.PublicBaseURL) != "",
		strings.TrimSpace(opts.SecretsBase) != "",
		strings.TrimSpace(opts.ScratchpadRootURI) != "",
		strings.TrimSpace(opts.ScratchpadUserID) != "",
		opts.AttachmentSourceSchemes,
		opts.ScratchpadTargetSchemes,
		opts.NamespaceClaimKeys,
	)

	// Derive callback base URL from listen address.
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
	// If azure-ref provided, derive missing values from secret (clientID, tenantID).
	if opts.AzureRef != "" {
		res := scy.EncodedResource(opts.AzureRef).Decode(context.Background(), cred.Azure{})
		sec, err := scy.New().Load(context.Background(), res)
		if err != nil {
			log.Fatalf("failed to load azure-ref secret: %v", err)
		}
		az, ok := sec.Target.(*cred.Azure)
		if !ok {
			log.Fatal("azure-ref secret is not of type cred.Azure (expected JSON with ClientID, TenantID, EncryptedClientSecret)")
		}
		if opts.ClientID == "" && az.ClientID != "" {
			opts.ClientID = az.ClientID
		}
		if (opts.TenantID == "" || opts.TenantID == "organizations") && az.TenantID != "" {
			opts.TenantID = az.TenantID
		}
	}

	svc := mcp.NewService(serviceConfigFromOptions(opts, baseURL))

	// Protected resource metadata for hosts that support OAuth2 challenge (future use)
	//protected := &authorization.Policy{
	//	Global: &authorization.Authorization{
	//		RequiredScopes: []string{"Mail.Read", "Mail.Send", "Calendars.ReadWrite", "Tasks.ReadWrite", "offline_access", "openid", "profile"},
	//		UseIdToken:     false,
	//		ProtectedResourceMetadata: &oauthmeta.ProtectedResourceMetadata{
	//			Resource:             "https://graph.microsoft.com",
	//			AuthorizationServers: []string{"https://login.microsoftonline.com/" + *tenantID + "/v2.0"},
	//			ScopesSupported:      []string{"Mail.Read", "Mail.Send", "Calendars.ReadWrite", "Tasks.ReadWrite"},
	//		},
	//	},
	//}
	//
	//authService, _ := auth.New(&auth.Config{Policy: protected})

	// Build server options baseline
	options := []mcpsrv.Option{
		mcpsrv.WithImplementation(schema.Implementation{Name: "mcp-outlook", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(mcp.NewHandler(svc)),
		mcpsrv.WithEndpointAddress(opts.HTTPAddr),
		mcpsrv.WithRootRedirect(true),
		mcpsrv.WithStreamableURI("/mcp"),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/device/", svc.DeviceHandler()),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/start", svc.DeviceStartHandler()),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/check", svc.DeviceCheckHandler()),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/reset", svc.DeviceResetHandler()),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/pending", svc.PendingListHandler()),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/pending/clear", svc.PendingClearHandler()),
	}

	// Optional server-level OAuth2
	if v := strings.TrimSpace(opts.Oauth2Config); v != "" {
		debugf("authorizer mode=server_oauth2 oauth2config_set=true use_id_token=%t", opts.UseIdToken)
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
			Global: &authorization.Authorization{
				UseIdToken: opts.UseIdToken,
				ProtectedResourceMetadata: &oauthmeta.ProtectedResourceMetadata{
					AuthorizationServers: []string{oc.Config.Endpoint.AuthURL},
				}},
			// Match sqlkit: allow SSE/UI without auth; protect /mcp
			ExcludeURI: "/sse,/ui/interaction/",
		}
		header := flow.AuthorizationExchangeHeader
		bff := &serverauth.BackendForFrontend{Client: &oc.Config, AuthorizationExchangeHeader: header}
		authSvc, err := serverauth.New(&serverauth.Config{Policy: authPolicy, BackendForFrontend: bff})
		if err != nil {
			log.Fatalf("failed to init auth service: %v", err)
		}

		// Add an always-on logging authorizer wrapper to classify presented tokens and BFF cookie.
		type statusWriter struct {
			http.ResponseWriter
			code int
		}
		//logMiddleware := func(next http.Handler) http.Handler {
		//	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//		ah := strings.TrimSpace(r.Header.Get("Authorization"))
		//		kind := "none"
		//		hasBFF := false
		//		if c, err := r.Cookie("BFF-Auth-Session"); err == nil && c != nil && c.Value != "" {
		//			hasBFF = true
		//		}
		//		if strings.HasPrefix(strings.ToLower(ah), "bearer ") {
		//			parts := strings.SplitN(ah, " ", 2)
		//			if len(parts) == 2 {
		//				tok := strings.TrimSpace(parts[1])
		//				var claims jwt.MapClaims
		//				if _, _, err := new(jwt.Parser).ParseUnverified(tok, &claims); err == nil {
		//					if _, ok := claims["scp"]; ok {
		//						kind = "access"
		//					} else {
		//						kind = "id-or-unknown"
		//					}
		//				} else {
		//					kind = "unparseable"
		//				}
		//			}
		//		}
		//		sw := &statusWriter{ResponseWriter: w, code: 200}
		//		authNext := authSvc.Middleware(next)
		//		authNext.ServeHTTP(http.ResponseWriter(sw), r)
		//		// Print request/response summary
		//			r.Method, r.URL.Path, r.RemoteAddr, sw.code, kind, opts.UseIdToken, hasBFF)
		//	})
		//}
		options = append(options,
			mcpsrv.WithAuthorizer(authSvc.Middleware),
			mcpsrv.WithProtectedResourcesHandler(authSvc.ProtectedResourcesHandler),
		)
	} else {
		debugf("authorizer mode=passive_bearer oauth2config_set=false")
		options = append(options, mcpsrv.WithAuthorizer(passiveBearerAuthorizer))
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

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func applyOptionDefaults(opts *Options) {
	if opts.SecretsBase == "" {
		opts.SecretsBase = "mem://localhost/mcp-outlook"
	}
	if opts.TenantID == "" {
		opts.TenantID = envOr("OUTLOOK_TENANT_ID", "organizations")
	}
	if opts.ClientID == "" {
		opts.ClientID = envOr("OUTLOOK_CLIENT_ID", "")
	}
	if opts.AzureRef == "" {
		opts.AzureRef = envOr("OUTLOOK_AZURE_REF", "")
	}
	if opts.ScratchpadRootURI == "" {
		opts.ScratchpadRootURI = envOr("OUTLOOK_SCRATCHPAD_ROOT_URI", "")
	}
	if opts.ScratchpadUserID == "" {
		opts.ScratchpadUserID = envOr("OUTLOOK_SCRATCHPAD_USER_ID", "")
	}
	if opts.AttachmentSourceSchemes == "" {
		opts.AttachmentSourceSchemes = envOr("OUTLOOK_ATTACHMENT_SOURCE_SCHEMES", "")
	}
	if opts.ScratchpadTargetSchemes == "" {
		opts.ScratchpadTargetSchemes = envOr("OUTLOOK_SCRATCHPAD_TARGET_SCHEMES", "")
	}
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	var result []string
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func serviceConfigFromOptions(opts Options, baseURL string) *mcp.Config {
	return &mcp.Config{
		ClientID:                opts.ClientID,
		TenantID:                opts.TenantID,
		SecretsBase:             strings.Replace(opts.SecretsBase, "$HOME", os.Getenv("HOME"), 1),
		CallbackBaseURL:         baseURL,
		AzureRef:                scy.EncodedResource(opts.AzureRef),
		ScratchpadRootURI:       strings.Replace(opts.ScratchpadRootURI, "$HOME", os.Getenv("HOME"), 1),
		ScratchpadUserID:        opts.ScratchpadUserID,
		AttachmentSourceSchemes: splitCSV(opts.AttachmentSourceSchemes),
		ScratchpadTargetSchemes: splitCSV(opts.ScratchpadTargetSchemes),
		NamespaceClaimKeys:      mcp.ParseNamespaceClaimKeys(opts.NamespaceClaimKeys),
	}
}

func debugf(format string, args ...any) {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("OUTLOOK_MCP_DEBUG")))
	if v == "" || v == "0" || v == "false" {
		return
	}
	log.Printf("[outlook-debug] "+format, args...)
}

func defaultStorageDir() string {
	dir, _ := os.UserConfigDir()
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "secret", "mcp-outlook")
}

func passiveBearerAuthorizer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token := strings.TrimSpace(r.Header.Get("Authorization")); token != "" {
			r = r.WithContext(context.WithValue(r.Context(), authorization.TokenKey, &authorization.Token{Token: token}))
		}
		next.ServeHTTP(w, r)
	})
}
