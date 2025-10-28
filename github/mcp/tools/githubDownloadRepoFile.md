Download a file by repository path without cloning.

Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- repo.owner and repo.name OR url: provide either explicit repo fields or a URL like "domain/owner/repo". If both are provided, url takes precedence.
- path (required): file path (e.g., "README.md", "src/main.go").
- ref (optional): branch, tag, or commit SHA; defaults to the repo's default branch if omitted.

Outputs:
- content: raw file bytes (base64-encoded in JSON).

Examples:
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "path":"README.md", "ref":"main"}
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "path":"path/to/file.go"}
