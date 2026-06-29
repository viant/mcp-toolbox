Send an email from the authenticated account.
Inputs:
- account.alias (required): stored account alias.
- to (required): list of recipient email addresses.
- subject (required): subject line.
- bodyText or bodyHtml: message body; provide one of them.
- importance (optional): Low | Normal | High.
- attachments (optional): file attachments for the message. Each item requires `name` and exactly one of:
  - `dataBase64`: base64-encoded file bytes.
  - `sourceURL`: readable AFS URL, such as `file:///tmp/report.pdf`.
  - `contentType` is optional; it is inferred from the filename when omitted.
- Attachments under 3 MB are sent with the simple Outlook send path. Attachments from 3 MB to 150 MB use Outlook large attachment upload sessions.
- Large attachments require the Microsoft Graph delegated `Mail.ReadWrite` permission in addition to mail send permission.

Example:
{"account":{"alias":"work"}, "to":["alice@example.com"], "subject":"Status Update", "bodyText":"All green."}

Example with base64 attachment:
{"account":{"alias":"work"}, "to":["alice@example.com"], "subject":"Report", "bodyText":"Attached.", "attachments":[{"name":"report.pdf", "contentType":"application/pdf", "dataBase64":"JVBERi0xLjc..."}]}

Example with file attachment:
{"account":{"alias":"work"}, "to":["alice@example.com"], "subject":"Report", "bodyText":"Attached.", "attachments":[{"name":"report.pdf", "sourceURL":"file:///tmp/report.pdf"}]}
