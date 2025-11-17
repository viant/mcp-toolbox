Posts a message to a Slack channel using the workspace bot token.

Inputs:
- alias: optional workspace alias selecting which stored token to use.
- channel: channel ID (e.g., C123...) or name like #general.
- text: plain text message (optional if blocks provided).
- blocks: optional JSON array with Slack Block Kit payload.
- threadTs: optional timestamp to reply in a thread.

Outputs:
- ok: boolean operation result.
- channel: channel ID where the message was posted.
- ts: message timestamp.
- error: error string when ok is false.

