List issues for a repository.
Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- repo.owner and repo.name OR url: provide either explicit repo fields or a URL like "domain/owner/repo". If both are provided, url takes precedence.
- state (optional): one of open | closed | all.

Auth: provide credentials for the alias+domain via OOB first. If alias is omitted and a single matching token exists, it is auto-selected.

Examples:
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "state":"open"}
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "state":"all"}
