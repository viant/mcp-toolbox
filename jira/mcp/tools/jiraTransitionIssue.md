Transition a Jira issue to a new status.

Inputs:
- account.alias: optional alias (defaults to "default").
- key: required issue key.
- transitionId: optional transition ID.
- transitionName: optional transition name (used if transitionId not provided).
- comment: optional comment to add after transition.
- fields/customFields: optional fields to set during transition.

Output:
- transitioned: true on success.
- transitionId: the transition ID used.
