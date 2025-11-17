package slackapi

// Slack Web API response contracts (minimal fields used by the service layer).

type ResponseMetadata struct {
	NextCursor string `json:"next_cursor"`
}

type Message struct {
	Ts       string `json:"ts"`
	User     string `json:"user"`
	Text     string `json:"text"`
	ThreadTS string `json:"thread_ts"`
	Subtype  string `json:"subtype"`
	BotID    string `json:"bot_id"`
}

type ConversationsHistoryResponse struct {
	OK               bool             `json:"ok"`
	Error            string           `json:"error"`
	HasMore          bool             `json:"has_more"`
	ResponseMetadata ResponseMetadata `json:"response_metadata"`
	Messages         []Message        `json:"messages"`
}

// ConversationsRepliesResponse mirrors conversations.history for thread replies.
type ConversationsRepliesResponse struct {
	OK               bool             `json:"ok"`
	Error            string           `json:"error"`
	HasMore          bool             `json:"has_more"`
	ResponseMetadata ResponseMetadata `json:"response_metadata"`
	Messages         []Message        `json:"messages"`
}

type ChannelLite struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	IsPrivate  bool   `json:"is_private"`
	IsArchived bool   `json:"is_archived"`
}

type ConversationsListResponse struct {
	OK               bool             `json:"ok"`
	Error            string           `json:"error"`
	Channels         []ChannelLite    `json:"channels"`
	ResponseMetadata ResponseMetadata `json:"response_metadata"`
}
