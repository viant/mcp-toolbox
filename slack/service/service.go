package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/viant/afs"
	oa "github.com/viant/mcp-toolbox/auth"
	slackapi "github.com/viant/mcp-toolbox/slack/api"
	nsprov "github.com/viant/mcp/server/namespace"
	"github.com/viant/scy"
)

// Service is a lightweight Slack Web API client with scy-backed secret storage.
type Service struct {
	useText     bool
	secretsBase string
	// tokens holds alias or ns|alias scoped tokens resolved from SecretsBase or TokenRef.
	mu     sync.RWMutex
	tokens map[string]string
	httpc  *http.Client
	auth   *oa.Service
	ns     *nsprov.DefaultProvider

	// defaultToken optionally loaded from TokenRef at startup.
	defaultToken string
}

func NewService(cfg *Config) *Service {
	if cfg == nil {
		cfg = &Config{}
	}
	svc := &Service{
		useText:     !cfg.UseData,
		secretsBase: strings.TrimRight(os.ExpandEnv(cfg.SecretsBase), "/"),
		tokens:      map[string]string{},
		httpc:       &http.Client{},
		auth:        oa.New(),
	}
	// Initialize namespace provider: prefer identity (email/sub) when available; fallback to token hash with prefix tkn-
	svc.ns = nsprov.NewProvider(&nsprov.Config{PreferIdentity: true, Hash: nsprov.HashConfig{Algorithm: "md5", Prefix: "tkn-"}, Path: nsprov.PathConfig{Prefix: "id-", Sanitize: true, MaxLen: 120}})
	if cfg.TokenRef != "" {
		if tok := loadTokenFromRef(cfg.TokenRef); tok != "" {
			svc.defaultToken = tok
		}
	}
	return svc
}

func loadTokenFromRef(ref scy.EncodedResource) string {
	res := ref.Decode(context.Background(), map[string]any{})
	sec, err := scy.New().Load(context.Background(), res)
	if err != nil || sec == nil || sec.Target == nil {
		return ""
	}
	switch v := sec.Target.(type) {
	case *string:
		return strings.TrimSpace(*v)
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		if t, ok := v["token"].(string); ok {
			return strings.TrimSpace(t)
		}
	default:
		// try JSON marshal -> map
		b, _ := json.Marshal(v)
		var mm map[string]any
		if json.Unmarshal(b, &mm) == nil {
			if t, ok := mm["token"].(string); ok {
				return strings.TrimSpace(t)
			}
		}
	}
	return ""
}

// UseTextField indicates if MCP results should be put in the text field.
func (s *Service) UseTextField() bool { return s.useText }

func (s *Service) tokenKey(ns, alias string) string {
	if ns == "" {
		ns = "default"
	}
	return ns + "|" + strings.TrimSpace(alias)
}

func (s *Service) loadToken(ctx context.Context, ns, alias string) string {
	// in-memory
	s.mu.RLock()
	t := s.tokens[s.tokenKey(ns, alias)]
	s.mu.RUnlock()
	if t != "" {
		return t
	}
	// secretsBase
	if s.secretsBase != "" {
		url := strings.Join([]string{s.secretsBase, "slack", safePart(ns), safePart(alias), "token"}, "/")
		if rc, err := afs.New().OpenURL(ctx, url); err == nil && rc != nil {
			data, _ := io.ReadAll(rc)
			_ = rc.Close()
			if len(data) > 0 {
				t = strings.TrimSpace(string(data))
				if t != "" {
					s.mu.Lock()
					s.tokens[s.tokenKey(ns, alias)] = t
					s.mu.Unlock()
					return t
				}
			}
		}
	}
	// default from TokenRef
	return s.defaultToken
}

func (s *Service) persistToken(ctx context.Context, ns, alias, token string) {
	if s.secretsBase == "" || strings.TrimSpace(token) == "" {
		return
	}
	url := strings.Join([]string{s.secretsBase, "slack", safePart(ns), safePart(alias), "token"}, "/")
	_ = afs.New().Upload(ctx, url, 0o600, bytes.NewReader([]byte(token)))
}

// safePart sanitizes a path segment (very similar to other services).
func safePart(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "_"
	}
	s = strings.ReplaceAll(s, "..", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "|", "_")
	return s
}

// PostMessage posts a message to a channel by ID or name.
func (s *Service) PostMessage(ctx context.Context, in *PostMessageInput) (*PostMessageOutput, error) {
	if in == nil {
		return nil, errors.New("nil input")
	}
	// Derive namespace using shared provider (identity preferred, fallback to token hash)
	desc, err := s.ns.Namespace(ctx)
	if err != nil {
		return nil, err
	}
	ns := desc.Name
	token := s.loadToken(ctx, ns, in.Alias)
	if token == "" {
		return nil, errors.New("missing slack token for alias; configure tokenRef or secretsBase")
	}

	channelID := strings.TrimSpace(in.Channel)
	if channelID == "" {
		return nil, errors.New("channel is required")
	}
	// If a name like #general is provided, attempt to resolve to ID.
	if strings.HasPrefix(channelID, "#") || !looksLikeID(channelID) {
		if id := s.findChannelID(ctx, token, strings.TrimPrefix(channelID, "#")); id != "" {
			channelID = id
		}
	}
	payload := map[string]any{"channel": channelID}
	if strings.TrimSpace(in.Text) != "" {
		payload["text"] = in.Text
	}
	if len(in.Blocks) > 0 {
		payload["blocks"] = json.RawMessage(in.Blocks)
	}
	if v := strings.TrimSpace(in.ThreadTS); v != "" {
		payload["thread_ts"] = v
	}
	body, _ := json.Marshal(payload)
	resp, err := s.api(ctx, token, http.MethodPost, "https://slack.com/api/chat.postMessage", body)
	if err != nil {
		return nil, err
	}
	var out struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Channel string `json:"channel"`
		Ts      string `json:"ts"`
	}
	_ = json.Unmarshal(resp, &out)
	if !out.OK {
		// Attempt auto-join for public channels if bot is not in channel (requires channels:join scope)
		if out.Error == "not_in_channel" {
			if jerr := s.joinChannel(ctx, token, channelID); jerr == nil {
				// retry once
				resp2, err2 := s.api(ctx, token, http.MethodPost, "https://slack.com/api/chat.postMessage", body)
				if err2 == nil {
					_ = json.Unmarshal(resp2, &out)
				}
			} else {
				// enrich error and return
				return &PostMessageOutput{OK: false, Error: jerr.Error()}, nil
			}
		}
		if out.Error == "not_allowed_token_type" {
			// Clearer guidance: use a Bot User OAuth Token (xoxb-...) with chat:write (and chat:write.public if needed)
			out.Error = "token not allowed for this method: use a bot token (xoxb-) with chat:write"
		} else if out.Error == "missing_scope" {
			out.Error = "missing scope: ensure chat:write (and chat:write.public for public channels)"
		}
		if out.Error == "" {
			out.Error = "unknown_error"
		}
		return &PostMessageOutput{OK: false, Error: out.Error}, nil
	}
	return &PostMessageOutput{OK: true, Channel: out.Channel, Ts: out.Ts}, nil
}

// ListChannels returns channels from conversations.list.
func (s *Service) ListChannels(ctx context.Context, in *ListChannelsInput) (*ListChannelsOutput, error) {
	if in == nil {
		in = &ListChannelsInput{}
	}
	desc, err := s.ns.Namespace(ctx)
	if err != nil {
		return nil, err
	}
	ns := desc.Name
	token := s.loadToken(ctx, ns, in.Alias)
	if token == "" {
		return nil, errors.New("missing slack token for alias; configure tokenRef or secretsBase")
	}
	// Build query
	limit := in.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	url := fmt.Sprintf("https://slack.com/api/conversations.list?limit=%d", limit)
	if c := strings.TrimSpace(in.Cursor); c != "" {
		url += "&cursor=" + strings.ReplaceAll(c, " ", "+")
	}
	resp, err := s.api(ctx, token, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	var rr struct {
		OK       bool   `json:"ok"`
		Error    string `json:"error"`
		Channels []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			IsPrivate  bool   `json:"is_private"`
			IsArchived bool   `json:"is_archived"`
		} `json:"channels"`
		ResponseMetadata struct {
			NextCursor string `json:"next_cursor"`
		} `json:"response_metadata"`
	}
	_ = json.Unmarshal(resp, &rr)
	if !rr.OK {
		errText := rr.Error
		if errText == "not_allowed_token_type" {
			errText = "token not allowed: use a bot token (xoxb-) with conversations:read"
		}
		if errText == "missing_scope" {
			errText = "missing scope: conversations:read"
		}
		return &ListChannelsOutput{Error: errText}, nil
	}
	out := &ListChannelsOutput{Channels: make([]Channel, 0, len(rr.Channels)), NextCursor: rr.ResponseMetadata.NextCursor}
	for _, c := range rr.Channels {
		out.Channels = append(out.Channels, Channel{ID: c.ID, Name: c.Name, Private: c.IsPrivate, Archived: c.IsArchived})
	}
	return out, nil
}

// findChannelID resolves channel name to ID using conversations.list paging (best-effort).
func (s *Service) findChannelID(ctx context.Context, token, name string) string {
	cursor := ""
	for i := 0; i < 3; i++ { // cap to avoid long scans
		url := "https://slack.com/api/conversations.list?limit=200"
		if cursor != "" {
			url += "&cursor=" + cursor
		}
		b, err := s.api(ctx, token, http.MethodGet, url, nil)
		if err != nil {
			return ""
		}
		var rr slackapi.ConversationsListResponse
		_ = json.Unmarshal(b, &rr)
		if !rr.OK {
			return ""
		}
		for _, c := range rr.Channels {
			if strings.EqualFold(c.Name, name) {
				return c.ID
			}
		}
		if rr.ResponseMetadata.NextCursor == "" {
			return ""
		}
		cursor = rr.ResponseMetadata.NextCursor
	}
	return ""
}

func looksLikeID(s string) bool {
	// rough check like C0123... or G0123...
	if len(s) < 9 {
		return false
	}
	if s[0] != 'C' && s[0] != 'G' && s[0] != 'D' && s[0] != 'T' {
		return false
	}
	return true
}

func (s *Service) api(ctx context.Context, token, method, url string, body []byte) ([]byte, error) {
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return nil, err
		}
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	res, err := s.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode/100 != 2 {
		return nil, fmt.Errorf("slack api %s returned %d: %s", url, res.StatusCode, string(data))
	}
	return data, nil
}

// joinChannel attempts to join a public channel. Requires channels:join scope on the bot token.
func (s *Service) joinChannel(ctx context.Context, token, channelID string) error {
	payload, _ := json.Marshal(map[string]any{"channel": channelID})
	resp, err := s.api(ctx, token, http.MethodPost, "https://slack.com/api/conversations.join", payload)
	if err != nil {
		return err
	}
	var jr struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(resp, &jr)
	if jr.OK {
		return nil
	}
	if jr.Error == "missing_scope" {
		return fmt.Errorf("missing scope: channels:join required to join public channels")
	}
	if jr.Error == "not_allowed_token_type" {
		return fmt.Errorf("token not allowed: use a bot token (xoxb-) with channels:join")
	}
	if jr.Error == "is_archived" {
		return fmt.Errorf("cannot join archived channel")
	}
	if jr.Error == "channel_not_found" {
		return fmt.Errorf("channel not found or not visible to bot")
	}
	if jr.Error == "method_not_supported_for_channel_type" {
		return fmt.Errorf("cannot join this channel type (private?). Invite the bot instead")
	}
	if jr.Error == "not_in_channel" {
		return fmt.Errorf("bot not a member and cannot auto-join (private channel?). Invite the bot")
	}
	if jr.Error == "" {
		jr.Error = "unknown_error"
	}
	return fmt.Errorf("%v", jr.Error)
}

// ListMessages reads channel history via conversations.history.
func (s *Service) ListMessages(ctx context.Context, in *ListMessagesInput) (*ListMessagesOutput, error) {
	if in == nil || strings.TrimSpace(in.Channel) == "" {
		return nil, errors.New("channel is required")
	}
	desc, err := s.ns.Namespace(ctx)
	if err != nil {
		return nil, err
	}
	ns := desc.Name
	token := s.loadToken(ctx, ns, in.Alias)
	if token == "" {
		return nil, errors.New("missing slack token for alias; configure tokenRef or secretsBase")
	}
	// Build query
	limit := in.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := fmt.Sprintf("channel=%s&limit=%d", strings.ReplaceAll(in.Channel, " ", "+"), limit)
	if c := strings.TrimSpace(in.Cursor); c != "" {
		q += "&cursor=" + strings.ReplaceAll(c, " ", "+")
	}
	if v := strings.TrimSpace(in.Oldest); v != "" {
		q += "&oldest=" + strings.ReplaceAll(v, " ", "+")
	}
	if v := strings.TrimSpace(in.Latest); v != "" {
		q += "&latest=" + strings.ReplaceAll(v, " ", "+")
	}
	url := "https://slack.com/api/conversations.history?" + q
	resp, err := s.api(ctx, token, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	var rr slackapi.ConversationsHistoryResponse
	_ = json.Unmarshal(resp, &rr)
	if !rr.OK {
		// Auto-join public channels if not in channel, then retry once
		if rr.Error == "not_in_channel" {
			if jerr := s.joinChannel(ctx, token, in.Channel); jerr == nil {
				// retry once
				resp2, err2 := s.api(ctx, token, http.MethodGet, url, nil)
				if err2 == nil {
					_ = json.Unmarshal(resp2, &rr)
				}
			} else {
				return &ListMessagesOutput{Error: jerr.Error()}, nil
			}
		}
		if !rr.OK {
			errText := rr.Error
			if errText == "not_allowed_token_type" {
				errText = "token not allowed: use a bot token (xoxb-) with conversations:history"
			}
			if errText == "missing_scope" {
				errText = "missing scope: conversations:history"
			}
			return &ListMessagesOutput{Error: errText}, nil
		}
	}
	out := &ListMessagesOutput{HasMore: rr.HasMore, NextCursor: rr.ResponseMetadata.NextCursor}
	for _, m := range rr.Messages {
		out.Messages = append(out.Messages, Message{Ts: m.Ts, User: m.User, Text: m.Text, ThreadTS: m.ThreadTS, Subtype: m.Subtype, BotID: m.BotID})
	}
	return out, nil
}

// ListThreadMessages reads replies of a thread via conversations.replies.
func (s *Service) ListThreadMessages(ctx context.Context, in *ListThreadMessagesInput) (*ListThreadMessagesOutput, error) {
	if in == nil {
		return nil, errors.New("nil input")
	}
	// If URL provided, derive channel and threadTs when missing
	if strings.TrimSpace(in.URL) != "" {
		if ch, _, thread, err := ParseSlackMessageURL(in.URL); err == nil {
			if strings.TrimSpace(in.Channel) == "" {
				in.Channel = ch
			}
			if strings.TrimSpace(in.ThreadTs) == "" {
				in.ThreadTs = thread
			}
		}
	}
	if strings.TrimSpace(in.Channel) == "" || strings.TrimSpace(in.ThreadTs) == "" {
		return nil, errors.New("channel and threadTs are required")
	}
	desc, err := s.ns.Namespace(ctx)
	if err != nil {
		return nil, err
	}
	ns := desc.Name
	token := s.loadToken(ctx, ns, in.Alias)
	if token == "" {
		return nil, errors.New("missing slack token for alias; configure tokenRef or secretsBase")
	}
	// Resolve channel name to ID when needed
	if strings.HasPrefix(in.Channel, "#") || !looksLikeID(in.Channel) {
		if id := s.findChannelID(ctx, token, strings.TrimPrefix(in.Channel, "#")); id != "" {
			in.Channel = id
		}
	}
	// Resolve channel name to ID when needed
	if strings.HasPrefix(in.Channel, "#") || !looksLikeID(in.Channel) {
		if id := s.findChannelID(ctx, token, strings.TrimPrefix(in.Channel, "#")); id != "" {
			in.Channel = id
		}
	}
	// Build query
	limit := in.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := fmt.Sprintf("channel=%s&ts=%s&limit=%d", strings.ReplaceAll(in.Channel, " ", "+"), strings.ReplaceAll(in.ThreadTs, " ", "+"), limit)
	if c := strings.TrimSpace(in.Cursor); c != "" {
		q += "&cursor=" + strings.ReplaceAll(c, " ", "+")
	}
	if v := strings.TrimSpace(in.Oldest); v != "" {
		q += "&oldest=" + strings.ReplaceAll(v, " ", "+")
	}
	if v := strings.TrimSpace(in.Latest); v != "" {
		q += "&latest=" + strings.ReplaceAll(v, " ", "+")
	}
	url := "https://slack.com/api/conversations.replies?" + q
	resp, err := s.api(ctx, token, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	var rr slackapi.ConversationsRepliesResponse
	_ = json.Unmarshal(resp, &rr)
	if !rr.OK {
		// Auto-join for public channels, then retry once
		if rr.Error == "not_in_channel" {
			if jerr := s.joinChannel(ctx, token, in.Channel); jerr == nil {
				resp2, err2 := s.api(ctx, token, http.MethodGet, url, nil)
				if err2 == nil {
					_ = json.Unmarshal(resp2, &rr)
				}
			} else {
				return &ListThreadMessagesOutput{Error: jerr.Error()}, nil
			}
		}
		if !rr.OK {
			errText := rr.Error
			if errText == "not_allowed_token_type" {
				errText = "token not allowed: use a bot token (xoxb-) with conversations:history"
			}
			if errText == "missing_scope" {
				errText = "missing scope: conversations:history"
			}
			return &ListThreadMessagesOutput{Error: errText}, nil
		}
	}
	out := &ListThreadMessagesOutput{HasMore: rr.HasMore, NextCursor: rr.ResponseMetadata.NextCursor}
	for _, m := range rr.Messages {
		out.Messages = append(out.Messages, Message{Ts: m.Ts, User: m.User, Text: m.Text, ThreadTS: m.ThreadTS, Subtype: m.Subtype, BotID: m.BotID})
	}
	return out, nil
}
