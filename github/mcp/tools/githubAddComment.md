Add a comment to an issue or PR.
Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- repo.owner and repo.name OR url: provide either explicit repo fields or a URL like "domain/owner/repo". If both are provided, url takes precedence.
- issueNumber (required): numeric issue or PR number.
- body (required): markdown or plain text comment.

Examples:
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "issueNumber":42, "body":"Thanks for the report!"}
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "issueNumber":101, "body":"LGTM ✅"}
