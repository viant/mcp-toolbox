Create a Jira issue in a project.

Inputs:
- account.alias: optional alias (defaults to "default").
- projectKey: required project key, e.g. "ABC".
- issueType: required type, e.g. "Task", "Bug", "Story".
- summary: required short title.
- description: optional markdown or plain text.

Output:
- issue: { id, key, title, url }.

