package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/viant/afs"
)

type MailService struct{ m *Manager }

func NewMailService(m *Manager) *MailService { return &MailService{m: m} }

const maxSimpleAttachmentBytes = 3000000
const maxLargeAttachmentBytes = 150 * 1000 * 1000
const largeAttachmentChunkBytes = 320 * 1024 * 12

var graphBaseURL = "https://graph.microsoft.com/v1.0"
var graphHTTPClient = http.DefaultClient

type resolvedEmailAttachment struct {
	Name        string
	ContentType string
	Data        []byte
	Size        int64
	Large       bool
}

func (s *MailService) List(ctx context.Context, in *ListMailInput, scopes []string, prompt func(string)) (*ListMailOutput, error) {
	if in.Top == 0 {
		in.Top = 10
	}
	// Build request via REST to avoid depending on SDK subpackages.
	q := neturl.Values{}
	if in.Top > 0 {
		q.Set("$top", fmt.Sprintf("%d", in.Top))
	}
	if len(in.OrderBy) > 0 {
		q.Set("$orderby", strings.Join(in.OrderBy, ","))
	} else {
		q.Set("$orderby", "receivedDateTime DESC")
	}
	if in.Filter != "" {
		q.Set("$filter", in.Filter)
	} else if in.SinceISO != "" || in.UntilISO != "" {
		filter := ""
		if in.SinceISO != "" {
			filter = fmt.Sprintf("receivedDateTime ge %s", in.SinceISO)
		}
		if in.UntilISO != "" {
			if filter != "" {
				filter += " and "
			}
			filter += fmt.Sprintf("receivedDateTime le %s", in.UntilISO)
		}
		if filter != "" {
			q.Set("$filter", filter)
		}
	}
	cred, err := s.m.Credential(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
	if err != nil {
		return nil, err
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
	if err != nil {
		return nil, err
	}
	url := "https://graph.microsoft.com/v1.0/me/messages?" + q.Encode()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list messages failed: %s: %s", resp.Status, readErrorBody(resp))
	}
	var payload struct {
		Value []struct {
			ID      string `json:"id"`
			Subject string `json:"subject"`
			From    struct {
				EmailAddress struct {
					Address string `json:"address"`
				} `json:"emailAddress"`
			} `json:"from"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	out := &ListMailOutput{}
	for i, m := range payload.Value {
		if in.Top > 0 && i >= in.Top {
			break
		}
		out.Messages = append(out.Messages, Message{ID: m.ID, Subject: m.Subject, From: m.From.EmailAddress.Address})
	}
	return out, nil
}

func (s *MailService) Send(ctx context.Context, in *SendEmailInput, scopes []string, prompt func(string)) error {
	cred, err := s.m.Credential(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
	if err != nil {
		return err
	}
	tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
	if err != nil {
		return err
	}
	attachments, hasLarge, err := resolveEmailAttachments(ctx, in.Attachments)
	if err != nil {
		return err
	}
	if hasLarge {
		return s.sendLargeMessage(ctx, tok.Token, in, attachments)
	}
	b, err := buildSendMailPayloadWithAttachments(in, attachments)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, graphBaseURL+"/me/sendMail", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := graphHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("sendMail failed: %s: %s", resp.Status, readErrorBody(resp))
	}
	return nil
}

func buildSendMailPayload(ctx context.Context, in *SendEmailInput) ([]byte, error) {
	attachments, hasLarge, err := resolveEmailAttachments(ctx, in.Attachments)
	if err != nil {
		return nil, err
	}
	if hasLarge {
		return nil, fmt.Errorf("attachments require Outlook large attachment upload sessions")
	}
	return buildSendMailPayloadWithAttachments(in, attachments)
}

func buildSendMailPayloadWithAttachments(in *SendEmailInput, attachments []resolvedEmailAttachment) ([]byte, error) {
	msg := buildGraphMessage(in)
	graphAttachments := buildGraphAttachmentPayloads(attachments)
	if len(graphAttachments) > 0 {
		msg["attachments"] = graphAttachments
	}
	payload := map[string]any{"message": msg, "saveToSentItems": true}
	return json.Marshal(payload)
}

func buildGraphMessage(in *SendEmailInput) map[string]any {
	type emailAddress struct {
		Address string `json:"address"`
	}
	type recipient struct {
		EmailAddress emailAddress `json:"emailAddress"`
	}
	type body struct {
		ContentType string `json:"contentType"`
		Content     string `json:"content"`
	}
	msg := map[string]any{"subject": in.Subject}
	if in.BodyHTML != "" {
		msg["body"] = body{ContentType: "HTML", Content: in.BodyHTML}
	} else {
		msg["body"] = body{ContentType: "Text", Content: in.BodyText}
	}
	var tos []recipient
	for _, a := range in.To {
		if a != "" {
			tos = append(tos, recipient{EmailAddress: emailAddress{Address: a}})
		}
	}
	msg["toRecipients"] = tos
	if in.Importance != "" {
		msg["importance"] = in.Importance
	}
	return msg
}

func buildGraphAttachmentPayloads(in []resolvedEmailAttachment) []map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(in))
	for _, attachment := range in {
		out = append(out, graphAttachmentPayload(attachment))
	}
	return out
}

func graphAttachmentPayload(attachment resolvedEmailAttachment) map[string]any {
	return map[string]any{
		"@odata.type":  "#microsoft.graph.fileAttachment",
		"name":         attachment.Name,
		"contentType":  attachment.ContentType,
		"contentBytes": base64.StdEncoding.EncodeToString(attachment.Data),
	}
}

func resolveEmailAttachments(ctx context.Context, in []EmailAttachment) ([]resolvedEmailAttachment, bool, error) {
	if len(in) == 0 {
		return nil, false, nil
	}
	var hasLarge bool
	out := make([]resolvedEmailAttachment, 0, len(in))
	for i, attachment := range in {
		name := strings.TrimSpace(attachment.Name)
		if name == "" {
			return nil, false, fmt.Errorf("attachments[%d].name is required", i)
		}
		hasData := strings.TrimSpace(attachment.DataBase64) != ""
		hasSource := strings.TrimSpace(attachment.SourceURL) != ""
		switch {
		case hasData && hasSource:
			return nil, false, fmt.Errorf("attachments[%d] must provide exactly one of dataBase64 or sourceURL", i)
		case !hasData && !hasSource:
			return nil, false, fmt.Errorf("attachments[%d] must provide dataBase64 or sourceURL", i)
		}

		var data []byte
		var err error
		if hasData {
			data, err = decodeAttachmentBase64(attachment.DataBase64)
		} else {
			data, err = readAttachmentSource(ctx, attachment.SourceURL)
		}
		if err != nil {
			return nil, false, fmt.Errorf("attachments[%d] %s: %w", i, name, err)
		}
		size := int64(len(data))
		if size > maxLargeAttachmentBytes {
			return nil, false, fmt.Errorf("attachments[%d] %s exceeds Outlook large attachment limit of 150 MB", i, name)
		}
		large := size >= maxSimpleAttachmentBytes
		hasLarge = hasLarge || large
		out = append(out, resolvedEmailAttachment{
			Name:        name,
			ContentType: attachmentContentType(attachment),
			Data:        data,
			Size:        size,
			Large:       large,
		})
	}
	return out, hasLarge, nil
}

func decodeAttachmentBase64(value string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(compactBase64(value))
	if err != nil {
		return nil, fmt.Errorf("invalid dataBase64")
	}
	return data, nil
}

func compactBase64(value string) string {
	replacer := strings.NewReplacer("\n", "", "\r", "", "\t", "", " ", "")
	return replacer.Replace(strings.TrimSpace(value))
}

func readAttachmentSource(ctx context.Context, sourceURL string) ([]byte, error) {
	sourceURL = strings.TrimSpace(sourceURL)
	if size, ok, err := localFileSize(sourceURL); err != nil {
		return nil, fmt.Errorf("read sourceURL: %w", err)
	} else if ok && size > maxLargeAttachmentBytes {
		return nil, fmt.Errorf("sourceURL exceeds Outlook large attachment limit of 150 MB")
	}
	rc, err := afs.New().OpenURL(ctx, sourceURL)
	if err != nil {
		return nil, fmt.Errorf("read sourceURL: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, maxLargeAttachmentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read sourceURL: %w", err)
	}
	if int64(len(data)) > maxLargeAttachmentBytes {
		return nil, fmt.Errorf("sourceURL exceeds Outlook large attachment limit of 150 MB")
	}
	return data, nil
}

func localFileSize(sourceURL string) (int64, bool, error) {
	u, err := neturl.Parse(sourceURL)
	if err != nil || u.Scheme != "file" {
		return 0, false, err
	}
	if u.Host != "" && u.Host != "localhost" {
		return 0, false, nil
	}
	path := u.Path
	if path == "" {
		path = strings.TrimPrefix(sourceURL, "file://")
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, true, err
	}
	return info.Size(), true, nil
}

func attachmentContentType(attachment EmailAttachment) string {
	if value := strings.TrimSpace(attachment.ContentType); value != "" {
		return value
	}
	if ext := filepath.Ext(attachment.Name); ext != "" {
		if value := mime.TypeByExtension(ext); value != "" {
			return value
		}
	}
	return "application/octet-stream"
}

func (s *MailService) sendLargeMessage(ctx context.Context, token string, in *SendEmailInput, attachments []resolvedEmailAttachment) error {
	messageID, err := s.createDraftMessage(ctx, token, in)
	if err != nil {
		return err
	}
	sent := false
	defer func() {
		if !sent {
			_ = s.deleteDraftMessage(context.Background(), token, messageID)
		}
	}()
	for _, attachment := range attachments {
		if attachment.Large {
			if err := s.uploadLargeAttachment(ctx, token, messageID, attachment); err != nil {
				return err
			}
			continue
		}
		if err := s.addSmallAttachmentToDraft(ctx, token, messageID, attachment); err != nil {
			return err
		}
	}
	if err := s.sendDraftMessage(ctx, token, messageID); err != nil {
		return err
	}
	sent = true
	return nil
}

func (s *MailService) createDraftMessage(ctx context.Context, token string, in *SendEmailInput) (string, error) {
	b, err := json.Marshal(buildGraphMessage(in))
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := doGraphJSON(ctx, token, http.MethodPost, graphBaseURL+"/me/messages", b, &out); err != nil {
		return "", fmt.Errorf("create draft message failed: %w", err)
	}
	if out.ID == "" {
		return "", fmt.Errorf("create draft message failed: missing message id")
	}
	return out.ID, nil
}

func (s *MailService) addSmallAttachmentToDraft(ctx context.Context, token, messageID string, attachment resolvedEmailAttachment) error {
	b, err := json.Marshal(graphAttachmentPayload(attachment))
	if err != nil {
		return err
	}
	url := graphBaseURL + "/me/messages/" + neturl.PathEscape(messageID) + "/attachments"
	if err := doGraphJSON(ctx, token, http.MethodPost, url, b, nil); err != nil {
		return fmt.Errorf("add attachment %q failed: %w", attachment.Name, err)
	}
	return nil
}

func (s *MailService) uploadLargeAttachment(ctx context.Context, token, messageID string, attachment resolvedEmailAttachment) error {
	uploadURL, err := s.createAttachmentUploadSession(ctx, token, messageID, attachment)
	if err != nil {
		return err
	}
	for start := int64(0); start < attachment.Size; start += largeAttachmentChunkBytes {
		end := start + largeAttachmentChunkBytes - 1
		if end >= attachment.Size {
			end = attachment.Size - 1
		}
		if err := uploadAttachmentChunk(ctx, uploadURL, attachment.Data[start:end+1], start, end, attachment.Size); err != nil {
			return fmt.Errorf("upload attachment %q failed: %w", attachment.Name, err)
		}
	}
	return nil
}

func (s *MailService) createAttachmentUploadSession(ctx context.Context, token, messageID string, attachment resolvedEmailAttachment) (string, error) {
	payload := map[string]any{
		"AttachmentItem": map[string]any{
			"attachmentType": "file",
			"name":           attachment.Name,
			"size":           attachment.Size,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	var out struct {
		UploadURL string `json:"uploadUrl"`
	}
	url := graphBaseURL + "/me/messages/" + neturl.PathEscape(messageID) + "/attachments/createUploadSession"
	if err := doGraphJSON(ctx, token, http.MethodPost, url, b, &out); err != nil {
		return "", fmt.Errorf("create upload session for %q failed: %w", attachment.Name, err)
	}
	if out.UploadURL == "" {
		return "", fmt.Errorf("create upload session for %q failed: missing uploadUrl", attachment.Name)
	}
	return out.UploadURL, nil
}

func uploadAttachmentChunk(ctx context.Context, uploadURL string, data []byte, start, end, total int64) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, uploadURL, bytes.NewReader(data))
	req.Header.Set("Content-Length", strconv.FormatInt(int64(len(data)), 10))
	req.Header.Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
	resp, err := graphHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, readErrorBody(resp))
	}
	return nil
}

func (s *MailService) sendDraftMessage(ctx context.Context, token, messageID string) error {
	url := graphBaseURL + "/me/messages/" + neturl.PathEscape(messageID) + "/send"
	if err := doGraphJSON(ctx, token, http.MethodPost, url, nil, nil); err != nil {
		return fmt.Errorf("send draft message failed: %w", err)
	}
	return nil
}

func (s *MailService) deleteDraftMessage(ctx context.Context, token, messageID string) error {
	url := graphBaseURL + "/me/messages/" + neturl.PathEscape(messageID)
	return doGraphJSON(ctx, token, http.MethodDelete, url, nil, nil)
}

func doGraphJSON(ctx context.Context, token, method, url string, body []byte, out any) error {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, _ := http.NewRequestWithContext(ctx, method, url, reader)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := graphHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", resp.Status, readErrorBody(resp))
	}
	if out != nil && resp.Body != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}

func readErrorBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(data))
}

func ptr[T any](v T) *T { return &v }
func ptrVal[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
