Checkout (clone) a GitHub repository to the local filesystem and optionally checkout a branch or commit.

Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- repo.owner and repo.name OR url: provide either explicit repo fields or a URL like "domain/owner/repo". If both are provided, url takes precedence.
- branch (optional): branch name to checkout.
- commit (optional): commit SHA to checkout (takes precedence over branch).
- destDir (optional): target directory for clone; if omitted a directory is created under the tool's storage dir.
- depth (optional): shallow clone depth (e.g., 1).

Outputs:
- path: local path of the checkout.
- checkedOut: branch or commit that was checked out.
- wasCloned: whether a fresh clone was performed.

Examples:
- {"account":{"alias":"work"}, "url":"github.vianttech.com/adelphic/repo", "branch":"main", "depth":1, "destDir":"/tmp/adelphic-repo"}
- {"account":{"alias":"work"}, "repo":{"owner":"adelphic","name":"repo"}, "commit":"abc1234"}
