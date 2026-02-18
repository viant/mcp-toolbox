List options for a Jira custom field context.

Inputs:
- account.alias (optional): account alias (default: "default").
- fieldId (required): Jira custom field id (e.g. "customfield_10571").
- contextId (required): context id from jiraListCustomFieldContexts.
- startAt (optional): pagination start.
- maxResults (optional): pagination size.

Output:
- options: list of {id, name, value}.
- isLast, startAt, maxResults, total.
