List calendar events in the next N days.
Inputs:
- account.alias (required): stored account alias.
- daysAhead (optional): default 7.
- filter (optional): OData $filter for events. Example: "start/dateTime ge 2025-01-01T00:00:00Z"
- orderBy (optional): array of OData $orderby fields. Example: ["start/dateTime DESC"]

Examples:
- Recent events ordered by start:
  {"account": {"alias": "work"}, "orderBy": ["start/dateTime DESC"]}
- Events starting after a date:
  {"account": {"alias": "work"}, "filter": "start/dateTime ge 2025-01-01T00:00:00Z"}
