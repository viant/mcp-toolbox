List worklogs for a Jira issue.

Inputs:
- account.alias: optional alias (defaults to "default").
- key: required issue key.
- startAt, maxResults: optional pagination.

Output:
- worklogs: array of { id, author, comment, created, updated, started, timeSpent, timeSpentSeconds }.
- startAt, maxResults, total.
