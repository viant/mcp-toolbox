List tasks from Microsoft To Do.
Requires a Bearer JWT with a configured non-empty identity claim; no default or token-hash namespace is accepted.
Inputs:
- account.alias (required): stored account alias.
- top (optional): max tasks (default 20).
- filter (optional): OData $filter applied per list. Example: "status eq 'notStarted'"
- orderBy (optional): array of OData $orderby fields applied per list. Example: ["createdDateTime DESC"]

Examples:
- Top 20 newest tasks:
  {"account": {"alias": "work"}, "top": 20, "orderBy": ["createdDateTime DESC"]}
- Only not started tasks:
  {"account": {"alias": "work"}, "filter": "status eq 'notStarted'", "top": 20}
