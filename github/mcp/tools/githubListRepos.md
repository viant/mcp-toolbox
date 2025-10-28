List repositories for the authenticated user.
Inputs:
- account.alias (required): stored account alias used for auth.
- account.domain (optional): GitHub host, default "github.com".
- visibility (optional): one of: all | public | private.
- affiliation (optional): comma-separated list of: owner,collaborator,organization_member.
- perPage (optional): page size (default 30).

Examples:
- {"account": {"alias": "work"}, "visibility": "all", "perPage": 50}
- {"account": {"alias": "work", "domain": "github.vianttech.com"}}
