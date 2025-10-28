Send an email from the authenticated account.
Inputs:
- account.alias (required): stored account alias.
- to (required): list of recipient email addresses.
- subject (required): subject line.
- bodyText or bodyHtml: message body; provide one of them.
- importance (optional): Low | Normal | High.

Example:
{"account":{"alias":"work"}, "to":["alice@example.com"], "subject":"Status Update", "bodyText":"All green."}
