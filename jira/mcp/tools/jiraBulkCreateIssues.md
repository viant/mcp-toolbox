Create multiple Jira issues in a single request.

Inputs:
- account.alias: optional alias (defaults to "default").
- issues: array of { projectKey, issueType, summary, description, assignee, reporter, priority, labels, components, fixVersions, versions, dueDate, parentKey, parentId, resolution, customFields }.

Output:
- raw: raw Jira bulk response.
