Send an email through Twilio SendGrid.

The MCP caller must have a configured non-empty identity claim. That identity is
also used to resolve per-user scratchpad attachments. The sender address is
provided by the caller and must already be verified by the configured SendGrid
account.

Inputs:
- `from` (required): bare sender email address.
- `fromName` (optional): sender display name.
- `to` (required): one or more recipient email addresses.
- `subject` (required): subject line.
- `bodyText` or `bodyHtml` (at least one required): message content. When both
  are present, both MIME alternatives are sent.
- `importance` (optional): `Low`, `Normal`, or `High`; defaults to `Normal`.
- `attachments` (optional, maximum 10): each item requires `name` and exactly
  one of:
  - `dataBase64`: base64-encoded file bytes.
  - `sourceURL`: an allowed AFS URL, such as
    `scratchpad://artifact/report-123`, `gs://bucket/report.pdf`, or
    `file:///tmp/report.pdf`.
  - `contentType` is optional and inferred from the filename when omitted.

SendGrid limits the complete message size. This server rejects decoded
attachments over 21,000,000 bytes in total and serialized provider payloads at
or above 29,000,000 bytes. Successful status `accepted` means SendGrid returned
HTTP 202; it does not mean the message was delivered.

Only for one logical serial hosted report-to-email delivery attempt, call this
tool at most once. Immediately after issuing that call, treat the attempt as
`EMAIL_ATTEMPTED` and stop regardless of success, error, timeout, or an
ambiguous result. Do not automatically retry within that attempt. A new
explicit user request, including an intentional resend, may start a new
attempt. This attempt rule does not constrain ordinary non-report email, and
one call may contain multiple approved recipients.

Example:
```json
{"from":"sender@example.com","fromName":"Example Service","to":["alice@example.com"],"subject":"Status Update","bodyText":"All green."}
```

Example with a scratchpad artifact:
```json
{"from":"sender@example.com","to":["alice@example.com"],"subject":"Report","bodyText":"Attached.","attachments":[{"name":"report.pdf","contentType":"application/pdf","sourceURL":"scratchpad://artifact/report-123"}]}
```
