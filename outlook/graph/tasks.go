package graph

import (
    "context"
    "encoding/json"
    "net/http"
    neturl "net/url"
    "strings"

    "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
    models "github.com/microsoftgraph/msgraph-sdk-go/models"
)

type TaskService struct{ m *Manager }

func NewTaskService(m *Manager) *TaskService { return &TaskService{m: m} }

func (s *TaskService) List(ctx context.Context, in *ListTasksInput, scopes []string, prompt func(string)) (*ListTasksOutput, error) {
    if in.Top == 0 { in.Top = 20 }
    client, err := s.m.Client(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
    if err != nil { return nil, err }
    lists, err := client.Me().Todo().Lists().Get(ctx, nil)
    if err != nil { return nil, err }
    // Acquire token for REST calls
    cred, err := s.m.Credential(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
    if err != nil { return nil, err }
    tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes}); if err != nil { return nil, err }
    out := &ListTasksOutput{}
    for _, l := range lists.GetValue() {
        if len(out.Tasks) >= in.Top { break }
        lid := ptrVal(l.GetId())
        q := neturl.Values{}
        if in.Filter != "" { q.Set("$filter", in.Filter) }
        if len(in.OrderBy) > 0 { q.Set("$orderby", strings.Join(in.OrderBy, ",")) }
        url := "https://graph.microsoft.com/v1.0/me/todo/lists/" + lid + "/tasks"; if enc := q.Encode(); enc != "" { url += "?"+enc }
        req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil); req.Header.Set("Authorization", "Bearer "+tok.Token)
        resp, err := http.DefaultClient.Do(req); if err != nil { continue }
        func(){ defer resp.Body.Close(); if resp.StatusCode >= 300 { return }; var payload struct{ Value []struct{ ID, Title string } `json:"value"` }; if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil { return }; for _, t := range payload.Value { if len(out.Tasks) >= in.Top { break }; out.Tasks = append(out.Tasks, Task{ID: t.ID, Title: t.Title}) } }()
    }
    return out, nil
}

func (s *TaskService) Create(ctx context.Context, in *CreateTaskInput, scopes []string, prompt func(string)) (*Task, error) {
	client, err := s.m.Client(ctx, in.Account.Alias, in.Account.TenantID, scopes, prompt)
	if err != nil {
		return nil, err
	}
	// Use default list (Tasks)
	lists, err := client.Me().Todo().Lists().Get(ctx, nil)
	if err != nil {
		return nil, err
	}
	var listID string
	if len(lists.GetValue()) > 0 {
		listID = ptrVal(lists.GetValue()[0].GetId())
	}
	task := models.NewTodoTask()
	task.SetTitle(ptr(in.Title))
	if in.BodyText != "" {
		body := models.NewItemBody()
		body.SetContentType(ptr(models.TEXT_BODYTYPE))
		body.SetContent(ptr(in.BodyText))
		task.SetBody(body)
	}
	created, err := client.Me().Todo().Lists().ByTodoTaskListId(listID).Tasks().Post(ctx, task, nil)
	if err != nil {
		return nil, err
	}
	return &Task{ID: ptrVal(created.GetId()), Title: ptrVal(created.GetTitle())}, nil
}
