Create an issue in a repository.
Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- repo.owner and repo.name OR url: provide either explicit repo fields or a URL like "domain/owner/repo". If both are provided, url takes precedence.
- title (required): issue title.
- body (optional): issue body.
- labels (optional): array of labels, e.g., ["bug", "help wanted"].
- assignees (optional): array of usernames, e.g., ["alice", "bob"].

Examples:
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "title":"Fix race in service", "labels":["bug"], "assignees":["alice"]}
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "title":"Improve logging"}
