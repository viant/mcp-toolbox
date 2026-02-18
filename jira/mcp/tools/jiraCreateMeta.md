Fetch Jira issue create metadata for a project and issue type.

Inputs:
- account.alias (optional): account alias (default: "default").
- projectKey (optional): project key, e.g. "ENG".
- issueType (optional): issue type name, e.g. "Task".
- expand (optional): Jira expand string. Defaults to "projects.issuetypes.fields".

Output:
- raw: the raw JSON payload from /rest/api/3/issue/createmeta.
