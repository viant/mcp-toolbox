Create a calendar event.
Inputs:
- account.alias (required): stored account alias.
- subject (required)
- startISO (required): RFC3339 date-time.
- endISO (required): RFC3339 date-time.
- timeZone (optional): default UTC.
- location (optional)
- attendees (optional): list of attendee emails.
- bodyText (optional)

Example:
{"account":{"alias":"work"}, "subject":"1:1", "startISO":"2025-02-01T10:00:00Z", "endISO":"2025-02-01T10:30:00Z", "attendees":["alice@example.com"]}
