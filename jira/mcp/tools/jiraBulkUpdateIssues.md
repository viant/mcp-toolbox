Update multiple Jira issues in a single request.

Inputs:
- account.alias: optional alias (defaults to "default").
- issues: array of { key or id, fields, customFields }.

Output:
- raw: raw Jira bulk response.
