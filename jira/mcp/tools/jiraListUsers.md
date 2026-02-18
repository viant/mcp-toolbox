Search Jira users by query.

Inputs:
- account.alias (optional): account alias (default: "default").
- query (required): text to search (name or email fragment).
- startAt (optional): pagination start.
- maxResults (optional): pagination size.

Output:
- users: list of {accountId, displayName, email, active}.
