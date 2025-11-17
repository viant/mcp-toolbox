Lists recent messages from a Slack channel.

Inputs:
- alias: optional workspace alias (default "default").
- channel: required channel ID (e.g., C123…); use slackListChannels to discover.
- cursor: pagination cursor from a previous call.
- limit: max messages (default 200; max 1000).
- oldest: optional start timestamp (inclusive).
- latest: optional end timestamp (exclusive).

Returns:
- messages: array of { ts, user, text, thread_ts, subtype, bot_id }.
- hasMore: true when more pages available.
- nextCursor: cursor for the next page.
- error: Slack error (if any), with friendly hints for token type/scope.
