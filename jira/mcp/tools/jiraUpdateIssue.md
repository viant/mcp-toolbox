Update fields on a Jira issue.

Inputs:
- account.alias: optional alias (defaults to "default").
- key: required issue key.
- summary, description, labels, components, fixVersions, versions, dueDate, assignee, reporter, priority, parentKey, parentId, resolution.
- customFields: optional map of customfield_* values.
- fields: optional raw fields map for advanced updates.

Output:
- updated: true on success.
