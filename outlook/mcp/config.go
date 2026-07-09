package mcp

import (
	"strings"

	"github.com/viant/scy"
)

var defaultNamespaceClaimKeys = []string{"email", "sub"}

// Config controls Outlook MCP server behaviour and authentication.
type Config struct {
	// Azure AD application (client) ID for Microsoft Graph.
	ClientID string `json:"clientID"`
	// Tenant ID or "organizations"/"common".
	TenantID string `json:"tenantID"`
	// Optional authority/issuer URL; defaults to https://login.microsoftonline.com.
	Authority string `json:"authority,omitempty"`
	// AuthFlow selects Microsoft Graph authentication flow: "device" or "auth-code".
	AuthFlow string `json:"authFlow,omitempty"`
	// OAuthRedirectPath is the local callback path used by auth-code flow.
	OAuthRedirectPath string `json:"oauthRedirectPath,omitempty"`
	// GraphScopes are delegated Microsoft Graph/OIDC scopes requested for Outlook tools.
	GraphScopes []string `json:"graphScopes,omitempty"`

	// SecretsBase is an AFS/scy base URL where auth records are persisted per namespace+alias.
	SecretsBase string `json:"secretsBase,omitempty"`

	// ScratchpadRootURI is the shared scratchpad root URI template used to resolve scratchpad:// attachments.
	ScratchpadRootURI string `json:"scratchpadRootURI,omitempty"`
	// ScratchpadUserID is the fallback user id used for local/no-auth scratchpad resolution.
	ScratchpadUserID string `json:"scratchpadUserID,omitempty"`
	// AttachmentSourceSchemes restricts attachment sourceURL schemes. Empty allows all supported AFS schemes.
	AttachmentSourceSchemes []string `json:"attachmentSourceSchemes,omitempty"`
	// ScratchpadTargetSchemes restricts the underlying sourceURL schemes after scratchpad artifact resolution.
	ScratchpadTargetSchemes []string `json:"scratchpadTargetSchemes,omitempty"`
	// NamespaceClaimKeys is wired from the CLI flag and controls JWT identity claim lookup order.
	NamespaceClaimKeys []string `json:"-"`

	// CallbackBaseURL is used to generate absolute URLs for OOB flows.
	// Example: http://localhost:7788
	CallbackBaseURL string `json:"callbackBaseURL,omitempty"`

	// If true, return tool results in the `data` field instead of `text`.
	UseData bool `json:"useData,omitempty"`
	// Legacy flag to force using text field.
	UseText bool `json:"useText,omitempty"`

	// AzureRef optionally points to an Azure OAuth2 client config stored as a scy resource.
	// It uses EncodedResource syntax: "<URL>|<kmsKey>", where the key part is optional.
	// Examples:
	//  - file-based:    "~/.secret/azure.yaml|blowfish://default"
	//  - GCP secret:    "gcp://secretmanager/projects/myproj/secrets/azure-cred|blowfish://default"
	//  - AWS secret:    "aws://secretmanager/us-west-2/secret/prod/azure-cred|blowfish://default"
	// The referenced content should unmarshal into github.com/viant/scy/cred.Azure.
	AzureRef scy.EncodedResource `json:"azureRef,omitempty"`
}

func ParseNamespaceClaimKeys(value string) []string {
	return NormalizeNamespaceClaimKeys(strings.Split(value, ","))
}

func NormalizeNamespaceClaimKeys(keys []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, key)
	}
	if len(result) == 0 {
		return append([]string(nil), defaultNamespaceClaimKeys...)
	}
	return result
}
