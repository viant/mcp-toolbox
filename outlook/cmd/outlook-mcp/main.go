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
	HTTPAddr       string `short:"a" long:"addr" description:"HTTP listen address (empty disables HTTP)"`
	ClientID       string `long:"client-id" description:"Azure AD application (client) ID"`
	TenantID       string `long:"tenant-id" description:"Tenant ID or 'organizations'"`
	SecretsBase    string `long:"secretsBase" description:"AFS/scy base URL for persisting auth records (e.g., mem://localhost/mcp-outlook)"`
	AzureRef       string `long:"azure-ref" description:"scy EncodedResource for Azure cred (e.g., gcp://...|blowfish://default)"`
	Oauth2Config   string `short:"o" long:"oauth2config" description:"Path to JSON OAuth2 configuration file (scy EncodedResource)"`
	BFFRedirectURI string `long:"bff-redirect-uri" description:"Redirect URI for Backend-For-Frontend OAuth flow (browser callback)"`
	UseIdToken     bool   `short:"i" long:"use-id-token" description:"Use ID token (instead of access token) for identity scoping"`
}

func main() {

	var opts Options
	if _, err := flags.NewParser(&opts, flags.Default).Parse(); err != nil {
		os.Exit(2)
	}
	// Apply simple defaults and env fallbacks
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
	if opts.ClientID == "" && opts.AzureRef == "" {
		log.Fatal("missing --client-id/OUTLOOK_CLIENT_ID (or provide --azure-ref / OUTLOOK_AZURE_REF)")
	}

	// Derive callback base URL from listen address.
	baseURL := "http://localhost"
	if opts.HTTPAddr != "" {
		hostport := opts.HTTPAddr
		if hostport[0] == ':' {
			hostport = "localhost" + hostport
		}
		baseURL = "http://" + hostport
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

	svc := mcp.NewService(&mcp.Config{
		ClientID:        opts.ClientID,
		TenantID:        opts.TenantID,
		SecretsBase:     strings.Replace(opts.SecretsBase, "$HOME", os.Getenv("HOME"), 1),
		CallbackBaseURL: baseURL,
		AzureRef:        scy.EncodedResource(opts.AzureRef),
	})

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
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/pending", svc.PendingListHandler()),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/pending/clear", svc.PendingClearHandler()),
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

func defaultStorageDir() string {
	dir, _ := os.UserConfigDir()
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, "secret", "mcp-outlook")
}
