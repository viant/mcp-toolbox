Search Jira issues using JQL for the selected account.

Inputs:
- account.alias: optional alias (defaults to "default").
- jql: required JQL string, e.g. "project = ABC AND status = 'To Do'".
- includeChangelog: optional boolean to include changelog in each issue.
- maxResults: optional max results.
- startAt: optional offset.

Output:
- issues: array of { id, key, title, status, url }.
- total: total matched issues.
