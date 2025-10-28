package graph

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    neturl "net/url"
    "strings"

    "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type MailService struct{ m *Manager }

func NewMailService(m *Manager) *MailService { return &MailService{m: m} }

func (s *MailService) List(ctx context.Context, in *ListMailInput, scopes []string, prompt func(string)) (*ListMailOutput, error) {
	if in.Top == 0 {
		in.Top = 10
	}
    // Build request via REST to avoid depending on SDK subpackages.
    q := neturl.Values{}
    if in.Top > 0 { q.Set("$top", fmt.Sprintf("%d", in.Top)) }
    if len(in.OrderBy) > 0 {
        q.Set("$orderby", strings.Join(in.OrderBy, ","))
    } else {
        q.Set("$orderby", "receivedDateTime DESC")
    }
    if in.Filter != "" {
        q.Set("$filter", in.Filter)
    } else if in.SinceISO != "" || in.UntilISO != "" {
        filter := ""
        if in.SinceISO != "" { filter = fmt.Sprintf("receivedDateTime ge %s", in.SinceISO) }
        if in.UntilISO != "" {
            if filter != "" { filter += " and " }
            filter += fmt.Sprintf("receivedDateTime le %s", in.UntilISO)
        }
        if filter != "" { q.Set("$filter", filter) }
    }
    cred, err := s.m.Credential(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
    if err != nil { return nil, err }
    tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
    if err != nil { return nil, err }
    url := "https://graph.microsoft.com/v1.0/me/messages?" + q.Encode()
    req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    req.Header.Set("Authorization", "Bearer "+tok.Token)
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return nil, err }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 { return nil, fmt.Errorf("list messages failed: %s", resp.Status) }
    var payload struct {
        Value []struct{
            ID string `json:"id"`
            Subject string `json:"subject"`
            From struct{ EmailAddress struct{ Address string `json:"address"` } `json:"emailAddress"` } `json:"from"`
        } `json:"value"`
    }
    if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil { return nil, err }
    out := &ListMailOutput{}
    for i, m := range payload.Value {
        if in.Top > 0 && i >= in.Top { break }
        out.Messages = append(out.Messages, Message{ID: m.ID, Subject: m.Subject, From: m.From.EmailAddress.Address})
    }
    return out, nil
}

func (s *MailService) Send(ctx context.Context, in *SendEmailInput, scopes []string, prompt func(string)) error {
    cred, err := s.m.Credential(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
    if err != nil { return err }
    tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
    if err != nil { return err }
    type emailAddress struct{ Address string `json:"address"` }
    type recipient struct{ EmailAddress emailAddress `json:"emailAddress"` }
    type body struct{ ContentType, Content string `json:"contentType","content"` }
    msg := map[string]any{"subject": in.Subject}
    if in.BodyHTML != "" {
        msg["body"] = body{ContentType: "HTML", Content: in.BodyHTML}
    } else {
        msg["body"] = body{ContentType: "Text", Content: in.BodyText}
    }
    var tos []recipient
    for _, a := range in.To {
        if a != "" { tos = append(tos, recipient{EmailAddress: emailAddress{Address: a}}) }
    }
    msg["toRecipients"] = tos
    if in.Importance != "" { msg["importance"] = in.Importance }
    payload := map[string]any{"message": msg, "saveToSentItems": true}
    b, _ := json.Marshal(payload)
    req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://graph.microsoft.com/v1.0/me/sendMail", bytes.NewReader(b))
    req.Header.Set("Authorization", "Bearer "+tok.Token)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    if err != nil { return err }
    defer resp.Body.Close()
    if resp.StatusCode >= 300 { return fmt.Errorf("sendMail failed: %s", resp.Status) }
    return nil
}

func ptr[T any](v T) *T { return &v }
func ptrVal[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
