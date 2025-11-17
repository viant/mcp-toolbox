package service

import "encoding/json"

type PostMessageInput struct {
	// Alias selects which Slack workspace token to use (maps to namespace+alias secret).
	Alias string `json:"alias,omitempty"`
	// Channel accepts a channel ID (e.g., C123...) or a name like #general.
	Channel string `json:"channel"`
	// Text is the plain text message. Optional when Blocks is provided.
	Text string `json:"text,omitempty"`
	// Blocks is an optional raw JSON array for Block Kit payload.
	Blocks json.RawMessage `json:"blocks,omitempty"`
	// ThreadTS posts as a reply when provided.
	ThreadTS string `json:"threadTs,omitempty"`
}

type PostMessageOutput struct {
	OK      bool   `json:"ok"`
	Channel string `json:"channel,omitempty"`
	Ts      string `json:"ts,omitempty"`
	Error   string `json:"error,omitempty"`
}

type ListChannelsInput struct {
	Alias  string `json:"alias,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

type Channel struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Private  bool   `json:"private"`
	Archived bool   `json:"archived"`
}

type ListChannelsOutput struct {
	Channels   []Channel `json:"channels"`
	NextCursor string    `json:"nextCursor,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// ListMessagesInput requests channel history.
type ListMessagesInput struct {
	Alias   string `json:"alias,omitempty"`
	Channel string `json:"channel"`
	Cursor  string `json:"cursor,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Oldest  string `json:"oldest,omitempty"`
	Latest  string `json:"latest,omitempty"`
}

type Message struct {
	Ts       string `json:"ts,omitempty"`
	User     string `json:"user,omitempty"`
	Text     string `json:"text,omitempty"`
	ThreadTS string `json:"thread_ts,omitempty"`
	Subtype  string `json:"subtype,omitempty"`
	BotID    string `json:"bot_id,omitempty"`
}

type ListMessagesOutput struct {
	Messages   []Message `json:"messages,omitempty"`
	HasMore    bool      `json:"hasMore,omitempty"`
	NextCursor string    `json:"nextCursor,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// ListThreadMessagesInput retrieves replies for a thread (parent ts required).
type ListThreadMessagesInput struct {
	Alias    string `json:"alias,omitempty"`
	Channel  string `json:"channel"`
	ThreadTs string `json:"threadTs"`
	Cursor   string `json:"cursor,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	Oldest   string `json:"oldest,omitempty"`
	Latest   string `json:"latest,omitempty"`
	// Optional Slack message URL (e.g., https://workspace.slack.com/archives/C123/p1700152345678900?thread_ts=1700152345.678900)
	// When provided, channel/threadTs may be derived from it.
	URL string `json:"url,omitempty"`
}

type ListThreadMessagesOutput struct {
	Messages   []Message `json:"messages,omitempty"`
	HasMore    bool      `json:"hasMore,omitempty"`
	NextCursor string    `json:"nextCursor,omitempty"`
	Error      string    `json:"error,omitempty"`
}
