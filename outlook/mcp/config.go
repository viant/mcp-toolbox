package mcp

import (
	"github.com/viant/scy"
)

// Config controls Outlook MCP server behaviour and authentication.
type Config struct {
	// Azure AD application (client) ID for Microsoft Graph.
	ClientID string `json:"clientID"`
	// Tenant ID or "organizations"/"common".
	TenantID string `json:"tenantID"`
	// Optional authority/issuer URL; defaults to https://login.microsoftonline.com.
	Authority string `json:"authority,omitempty"`

	// StorageDir is where auth records/caches are persisted per account alias.
	StorageDir string `json:"storageDir,omitempty"`

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
