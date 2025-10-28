List recent emails for the specified account.
Inputs:
- account.alias (required): stored account alias.
- top (optional): number of messages to return.
- sinceISO/untilISO (optional): RFC3339 timestamps to filter by received date (inclusive). Example: sinceISO: 2025-01-01T00:00:00Z
- filter (optional): OData $filter expression for advanced querying. Example: "receivedDateTime ge 2025-01-01T00:00:00Z and from/emailAddress/address eq 'alice@example.com'"
- orderBy (optional): array of OData $orderby fields. Example: ["receivedDateTime DESC", "subject ASC"]

Examples:
- Recent 50 messages since a date:
  {"account": {"alias": "work"}, "top": 50, "sinceISO": "2025-01-01T00:00:00Z"}
- Filter by sender and date, newest first:
  {"account": {"alias": "work"}, "filter": "receivedDateTime ge 2025-01-01T00:00:00Z and from/emailAddress/address eq 'alice@example.com'", "orderBy": ["receivedDateTime DESC"], "top": 25}
