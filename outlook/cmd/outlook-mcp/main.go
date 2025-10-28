package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/viant/mcp-protocol/schema"
	"github.com/viant/mcp-toolbox/outlook/mcp"
	mcpsrv "github.com/viant/mcp/server"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	_ "github.com/viant/scy/kms/blowfish"
)

var (
	addr     = flag.String("addr", ":7788", "HTTP listen address")
	clientID = flag.String("client-id", envOr("OUTLOOK_CLIENT_ID", ""), "Azure AD application (client) ID")
	tenantID = flag.String("tenant-id", envOr("OUTLOOK_TENANT_ID", "organizations"), "Tenant ID or 'organizations'")
	storage  = flag.String("storage", defaultStorageDir(), "Directory for auth records/cache")
	azureRef = flag.String("azure-ref", envOr("OUTLOOK_AZURE_REF", ""), "scy EncodedResource for Azure cred (e.g., gcp://...|blowfish://default)")
)

func main() {
	os.Args = []string{"", "-addr", ":7788", "-storage", "$HOME/.config/mcp-outlook", "-azure-ref", "~/.secret/azure.enc|blowfish://default"}
	flag.Parse()
	if *clientID == "" && *azureRef == "" {
		log.Fatal("missing --client-id/OUTLOOK_CLIENT_ID (or provide --azure-ref / OUTLOOK_AZURE_REF)")
	}

	// Derive callback base URL from listen address.
	baseURL := "http://localhost"
	if *addr != "" {
		hostport := *addr
		if hostport[0] == ':' {
			hostport = "localhost" + hostport
		}
		baseURL = "http://" + hostport
	}
	// If azure-ref provided, derive missing values from secret (clientID, tenantID).
	if *azureRef != "" {
		res := scy.EncodedResource(*azureRef).Decode(context.Background(), cred.Azure{})
		sec, err := scy.New().Load(context.Background(), res)
		if err != nil {
			log.Fatalf("failed to load azure-ref secret: %v", err)
		}
		az, ok := sec.Target.(*cred.Azure)
		if !ok {
			log.Fatal("azure-ref secret is not of type cred.Azure (expected JSON with ClientID, TenantID, EncryptedClientSecret)")
		}
		if *clientID == "" && az.ClientID != "" {
			*clientID = az.ClientID
		}
		if (*tenantID == "" || *tenantID == "organizations") && az.TenantID != "" {
			*tenantID = az.TenantID
		}
	}

	svc := mcp.NewService(&mcp.Config{
		ClientID:        *clientID,
		TenantID:        *tenantID,
		StorageDir:      strings.Replace(*storage, "$HOME", os.Getenv("HOME"), 1),
		CallbackBaseURL: baseURL,
		AzureRef:        scy.EncodedResource(*azureRef),
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

	server, err := mcpsrv.New(
		mcpsrv.WithImplementation(schema.Implementation{Name: "mcp-outlook", Version: "0.1.0"}),
		mcpsrv.WithNewHandler(mcp.NewHandler(svc)),
		mcpsrv.WithEndpointAddress(*addr),
		mcpsrv.WithRootRedirect(true),
		//	mcpsrv.WithAuthorizer(authService.Middleware),
		//	mcpsrv.WithProtectedResourcesHandler(authService.ProtectedResourcesHandler),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/device/", svc.DeviceHandler()),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/pending", svc.PendingListHandler()),
		mcpsrv.WithCustomHTTPHandler("/outlook/auth/pending/clear", svc.PendingClearHandler()),
	)
	if err != nil {
		log.Fatal(err)
	}
	if err := server.HTTP(context.Background(), *addr).ListenAndServe(); err != nil {
		log.Fatal(err)
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
