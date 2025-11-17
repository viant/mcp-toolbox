Lists channels from the Slack workspace associated with the current alias.

Inputs:
- alias: optional workspace alias selecting which stored token to use.
- limit: optional page size (default 200, max 1000).
- cursor: optional next_cursor for pagination.

Outputs:
- channels: array of channels {id, name, private, archived}.
- nextCursor: pagination cursor when more results are available.
- error: error string when the request fails.

