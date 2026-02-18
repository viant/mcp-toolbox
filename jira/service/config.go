package service

// Config holds Jira MCP service configuration.
// If Accounts is empty, the service attempts to read defaults from environment variables:
//   - JIRA_BASE_URL, JIRA_EMAIL, JIRA_TOKEN mapped to alias "default".
type Config struct {
	// UseData selects MCP structured content over text field when true.
	UseData bool
	// CallbackBaseURL base for OOB auth pages.
	CallbackBaseURL string
	// Accounts keyed by alias.
	Accounts map[string]Account
	// SecretsBase is an AFS/scy base URL to persist PATs per namespace+alias.
	SecretsBase string
}

// Account represents Jira connection parameters.
type Account struct {
	Alias   string // optional; set from key when empty
	BaseURL string // e.g. https://your-domain.atlassian.net
	Email   string // account email for API token auth
	Token   string // API token (Cloud) or PAT
}
