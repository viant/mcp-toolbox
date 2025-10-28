Search issues and pull requests.
Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- query (required): GitHub search query string (supports qualifiers).
- perPage (optional): page size.

Examples:
- {"account":{"alias":"work"}, "query":"repo:adelphic/repo is:issue is:open label:bug"}
- {"account":{"alias":"work"}, "query":"org:adelphic is:pr author:@me"}
