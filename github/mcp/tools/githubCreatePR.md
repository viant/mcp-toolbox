Create a pull request.
Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- repo.owner and repo.name OR url: provide either explicit repo fields or a URL like "domain/owner/repo". If both are provided, url takes precedence.
- title (required): PR title.
- head (required): source branch or user:branch.
- base (required): target branch.
- body (optional): PR description.
- draft (optional): true to open as draft.

Examples:
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "title":"Add GitHub MCP", "head":"feature/github-mcp", "base":"main", "draft":true}
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "title":"Bugfix", "head":"fix/edge-case", "base":"release"}
