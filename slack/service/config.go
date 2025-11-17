package service

import "github.com/viant/scy"

// Config controls Slack client behaviour and secret handling.
type Config struct {
	// SecretsBase is an AFS/scy base URL where per-namespace+alias Slack tokens are stored.
	// Example: mem://localhost/mcp-slack or file://~/.mcp/slack or scy://project/secret/slack
	SecretsBase string `json:"secretsBase,omitempty"`

	// TokenRef optionally points to a scy secret containing a Slack bot token.
	// If provided, it is used as a default token for all aliases unless overridden
	// by a per-namespace secret entry under SecretsBase.
	// The referenced content should be a plain string (the token) or JSON {"token":"xoxb-..."}.
	TokenRef scy.EncodedResource `json:"tokenRef,omitempty"`

	// UseData makes MCP results use structured content instead of text.
	UseData bool `json:"useData,omitempty"`
}
