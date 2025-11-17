Lists messages (replies) for a Slack thread.

Inputs:
- alias: optional workspace alias (default "default").
- channel: required channel ID (e.g., C123…). Use slackListChannels to discover.
- threadTs: required parent message ts of the thread.
- cursor: pagination cursor from a previous call.
- limit: max messages (default 200; max 1000).
- oldest/latest: optional time bounds for filtering.

Returns:
- messages: array of { ts, user, text, thread_ts, subtype, bot_id }.
- hasMore: true when more pages available.
- nextCursor: cursor for the next page.
- error: Slack error (if any), with friendly hints for token type/scope.
