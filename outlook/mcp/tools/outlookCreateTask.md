Create a new task in the default list.
Inputs:
- account.alias (required): stored account alias.
- title (required): task title.
- bodyText (optional): description.
- dueISO (optional): due date-time in RFC3339.

Example:
{"account":{"alias":"work"}, "title":"Follow up with vendor", "dueISO":"2025-02-05T17:00:00Z"}
