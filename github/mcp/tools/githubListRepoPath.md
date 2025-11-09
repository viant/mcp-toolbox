List directory contents or a single file without cloning.

Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- repo.owner and repo.name OR url: provide either explicit repo fields or a URL like "domain/owner/repo". If both are provided, url takes precedence.
- path (optional): directory or file path; default "/" (repo root).
- recursive (optional): true to traverse recursively (uses Git Trees API).
- include (optional): glob-like patterns to include (e.g., ["*.go","*.sql"]).
- exclude (optional): glob-like patterns to exclude (e.g., ["*_test.go","**/vendor/**"]).
- contains (optional): return only entries whose name or path contains this substring.
- concurrency (optional): number of concurrent directory fetches when recursive (default 6).
- ref (optional): branch, tag, or commit; defaults to repo default branch.
- findInFilesInclude (optional): array of patterns; include files whose contents match any. Default substring; use "/regex/" for RE2.
- findInFilesExclude (optional): array of patterns; exclude files whose contents match any. Default substring; use "/regex/" for RE2.
- findInFilesCaseInsensitive (optional): true to make substring matching case-insensitive (regex can use (?i)).
- skipBinary (optional): true to skip binary-like files when content matching (default true).
- maxFileSize (optional): max bytes to scan for content matching; larger files are skipped.

Auth:
- Provide credentials for the alias+domain first (via OOB page or /github/auth/token). If your server forces an alias, that alias is used.

Outputs:
- items: array of entries {type, name, path, size, sha}.
- warning (optional): non-fatal message when content search fell back to path-only (e.g., snapshot unavailable).

Examples:
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "path":"/", "recursive":false}
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "path":"services/pricing", "recursive":true, "include":["*.go","*.sql"], "exclude":["*_test.go"], "contains":"service"}
