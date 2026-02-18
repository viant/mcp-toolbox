Get a Jira issue by key.

Inputs:
- account.alias: optional alias (defaults to "default").
- key: required issue key (e.g., ENG-123).
- fields: optional list of fields to return (defaults to *all).

Output:
- issue: { id, key, title, status, url, fieldsRaw, customFields }.
