List comments on an issue or PR.
Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- repo.owner and repo.name OR url: provide either explicit repo fields or a URL like "domain/owner/repo". If both are provided, url takes precedence.
- issueNumber (required): numeric issue or PR number.

Examples:
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "issueNumber":42}
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "issueNumber":42}
