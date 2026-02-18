package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	oa "github.com/viant/mcp-toolbox/auth"

	jira "github.com/andygrunwald/go-jira"
	"github.com/trivago/tgo/tcontainer"
)

// Service provides Jira operations backed by a Go SDK client.
type Service struct {
	useText bool
	auth    *oa.Service
	cfg     *Config

	mu      sync.RWMutex
	clients map[string]*jira.Client // key: namespace|alias
	accts   map[string]Account      // resolved accounts per namespace|alias

	baseURL     string
	secretsBase string

	// In-memory tokens keyed by ns|alias|domain host
	tokens map[string]string
	emails map[string]string

	// singleflight gate per ns|alias|domain
	credMu    sync.Mutex
	credLocks map[string]chan struct{}
}

func NewService(cfg *Config) *Service {
	if cfg == nil {
		cfg = &Config{}
	}
	useText := !cfg.UseData
	s := &Service{
		useText:     useText,
		auth:        oa.New(),
		cfg:         cfg,
		clients:     map[string]*jira.Client{},
		accts:       map[string]Account{},
		baseURL:     strings.TrimRight(cfg.CallbackBaseURL, "/"),
		secretsBase: cfg.SecretsBase,
		tokens:      map[string]string{},
		emails:      map[string]string{},
		credLocks:   map[string]chan struct{}{},
	}
	return s
}

func (s *Service) UseTextField() bool      { return s.useText }
func (s *Service) CallbackBaseURL() string { return s.cfg.CallbackBaseURL }

// Namespace returns the effective authorization namespace for this request context.
func (s *Service) Namespace(ctx context.Context) string {
	if d, err := s.auth.Namespace(ctx); err == nil && d != "" {
		return d
	}
	return "default"
}
func (s *Service) BaseDomain() string {
	base := s.cfg.Accounts["default"].BaseURL
	if base == "" {
		base = os.Getenv("JIRA_BASE_URL")
	}
	if base == "" {
		return ""
	}
	if u, e := url.Parse(base); e == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
}

// account resolves an Account for namespace and alias.
func (s *Service) account(ctx context.Context, alias string) (Account, error) {
	if alias == "" {
		alias = "default"
	}
	ns := s.Namespace(ctx)
	key := ns + "|" + alias
	// cached account
	s.mu.RLock()
	if a, ok := s.accts[key]; ok {
		s.mu.RUnlock()
		return a, nil
	}
	s.mu.RUnlock()

	// build from config or env
	var acct Account
	if s.cfg != nil && s.cfg.Accounts != nil {
		if v, ok := s.cfg.Accounts[alias]; ok {
			acct = v
		}
	}
	if acct.BaseURL == "" {
		if v := os.Getenv("JIRA_BASE_URL"); v != "" {
			acct.BaseURL = v
		}
	}
	if acct.Email == "" {
		if v := os.Getenv("JIRA_EMAIL"); v != "" {
			acct.Email = v
		}
	}
	if acct.Token == "" {
		if v := os.Getenv("JIRA_TOKEN"); v != "" {
			acct.Token = v
		}
	}
	if acct.Alias == "" {
		acct.Alias = alias
	}
	if acct.BaseURL == "" || acct.Token == "" || acct.Email == "" {
		return Account{}, errors.New("missing Jira credentials: require baseURL, email, token (env: JIRA_BASE_URL,JIRA_EMAIL,JIRA_TOKEN)")
	}
	// Normalize base URL
	if !strings.HasPrefix(acct.BaseURL, "http") {
		acct.BaseURL = "https://" + acct.BaseURL
	}
	if _, err := url.Parse(acct.BaseURL); err != nil {
		return Account{}, fmt.Errorf("invalid baseURL: %w", err)
	}
	// cache and return
	s.mu.Lock()
	s.accts[key] = acct
	s.mu.Unlock()
	return acct, nil
}

// client returns a cached Jira client for namespace/alias.
func (s *Service) client(ctx context.Context, alias string) (*jira.Client, Account, error) {
	if alias == "" {
		alias = "default"
	}
	ns := s.Namespace(ctx)
	key := ns + "|" + alias
	s.mu.RLock()
	if c := s.clients[key]; c != nil {
		a := s.accts[key]
		s.mu.RUnlock()
		return c, a, nil
	}
	s.mu.RUnlock()
	acct, err := s.account(ctx, alias)
	if err != nil {
		return nil, Account{}, err
	}
	// Allow token/email override via in-memory tokens (OOB ingest)
	if acct.Token == "" || acct.Email == "" {
		// derive domain host
		host := acct.BaseURL
		if u, e := url.Parse(host); e == nil && u.Host != "" {
			host = u.Host
		}
		ns := s.Namespace(ctx)
		key := ns + "|" + alias + "|" + host
		s.mu.RLock()
		tok := s.tokens[key]
		em := s.emails[key]
		s.mu.RUnlock()
		if tok != "" && em != "" {
			acct.Token = tok
			acct.Email = em
		}
	}
	tp := jira.BasicAuthTransport{Username: acct.Email, Password: acct.Token}
	cli, err := jira.NewClient(tp.Client(), acct.BaseURL)
	if err != nil {
		return nil, Account{}, err
	}
	s.mu.Lock()
	s.clients[key] = cli
	s.accts[key] = acct
	s.mu.Unlock()
	return cli, acct, nil
}

// acquireCredLock provides a singleflight-style gate per (ns,alias,domain).
// Returns: leader flag, done channel (closed on success), and release func(success) to cleanup.
func (s *Service) AcquireCredLock(ns, alias, domain string) (bool, <-chan struct{}, func(success bool)) {
	key := ns + "|" + alias + "|" + domain
	s.credMu.Lock()
	if ch, ok := s.credLocks[key]; ok {
		s.credMu.Unlock()
		return false, ch, func(bool) {}
	}
	ch := make(chan struct{})
	s.credLocks[key] = ch
	s.credMu.Unlock()
	release := func(success bool) {
		s.credMu.Lock()
		cur, ok := s.credLocks[key]
		if ok {
			delete(s.credLocks, key)
			if success {
				close(cur)
			}
		}
		s.credMu.Unlock()
	}
	return true, ch, release
}

// notifyToken wakes any goroutines waiting for a token for (ns,alias,domain).
func (s *Service) notifyToken(ns, alias, domain string) {
	key := ns + "|" + alias + "|" + domain
	s.credMu.Lock()
	if ch, ok := s.credLocks[key]; ok {
		delete(s.credLocks, key)
		close(ch)
	}
	s.credMu.Unlock()
}

// ListProjects lists accessible projects.
func (s *Service) ListProjects(ctx context.Context, in *ListProjectsInput) (*ListProjectsOutput, error) {
	cli, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	// Try via SDK first; various versions return different shapes; if it fails, fall back to REST call.
	type projLite struct{ ID, Key, Name string }
	var items []projLite
	if cli != nil && cli.Project != nil {
		if list, _, e := cli.Project.GetList(); e == nil && list != nil {
			// Attempt to marshal and unmarshal generically to tolerate different shapes
			if b, mErr := json.Marshal(list); mErr == nil {
				var via struct {
					Values []projLite `json:"values"`
				}
				if json.Unmarshal(b, &via) == nil && len(via.Values) > 0 {
					items = via.Values
				} else {
					var arr []projLite
					if json.Unmarshal(b, &arr) == nil && len(arr) > 0 {
						items = arr
					}
				}
			}
		}
	}
	if len(items) == 0 {
		// Fallback REST: GET /rest/api/2/project
		b, e := s.jiraGET(ctx, acct, "/rest/api/2/project", "")
		if e != nil {
			return nil, e
		}
		var arr []struct{ ID, Key, Name string }
		_ = json.Unmarshal(b, &arr)
		for _, v := range arr {
			items = append(items, projLite{ID: v.ID, Key: v.Key, Name: v.Name})
		}
	}
	out := &ListProjectsOutput{Projects: make([]Project, 0, len(items))}
	for _, p := range items {
		out.Projects = append(out.Projects, Project{ID: p.ID, Key: p.Key, Name: p.Name})
	}
	return out, nil
}

// SearchIssues executes JQL and returns compact issue info.
func (s *Service) SearchIssues(ctx context.Context, in *SearchIssuesInput) (*SearchIssuesOutput, error) {
	jql := strings.TrimSpace(in.JQL)
	if jql == "" {
		jql = buildJQL(in)
	}
	if jql == "" {
		return nil, errors.New("jql or structured filters are required")
	}
	fields := normalizeJiraFields(in.Fields)
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	// Use REST v3 search API only.
	q := url.Values{}
	q.Set("jql", jql)
	q.Set("fields", fields)
	if in.IncludeChangelog {
		q.Set("expand", "changelog")
	}
	if in.MaxResults > 0 {
		q.Set("maxResults", strconv.Itoa(in.MaxResults))
	}
	if in.StartAt > 0 {
		q.Set("startAt", strconv.Itoa(in.StartAt))
	}
	b, e := s.jiraGET(ctx, acct, "/rest/api/3/search/jql", q.Encode())
	if e != nil {
		return nil, e
	}
	var resp struct {
		Total  int `json:"total"`
		Issues []struct {
			ID        string          `json:"id"`
			Key       string          `json:"key"`
			FieldsRaw json.RawMessage `json:"fields"`
			Changelog map[string]any  `json:"changelog"`
		} `json:"issues"`
	}
	if json.Unmarshal(b, &resp) != nil {
		return nil, errors.New("failed to parse jira search response")
	}
	out := &SearchIssuesOutput{Total: resp.Total}
	for _, it := range resp.Issues {
		fieldsRaw := extractFieldsFromRaw(it.FieldsRaw)
		summary := getString(fieldsRaw, "summary")
		status := getNestedString(fieldsRaw, "status", "name")
		statusCategory := getNestedString(fieldsRaw, "status", "statusCategory", "name")
		created := getString(fieldsRaw, "created")
		updated := getString(fieldsRaw, "updated")
		resolutionDate := getString(fieldsRaw, "resolutiondate")
		dueDate := getString(fieldsRaw, "duedate")
		assignee := getNestedString(fieldsRaw, "assignee", "displayName")
		reporter := getNestedString(fieldsRaw, "reporter", "displayName")
		priority := getNestedString(fieldsRaw, "priority", "name")
		issueType := getNestedString(fieldsRaw, "issuetype", "name")
		projectKey := getNestedString(fieldsRaw, "project", "key")
		projectName := getNestedString(fieldsRaw, "project", "name")
		labels := getStringSlice(fieldsRaw, "labels")
		components := getStringSliceFromObjArray(fieldsRaw, "components", "name")
		resolution := getNestedString(fieldsRaw, "resolution", "name")
		parentKey := getNestedString(fieldsRaw, "parent", "key")
		parentID := getNestedString(fieldsRaw, "parent", "id")
		fixVersions := getStringSliceFromObjArray(fieldsRaw, "fixVersions", "name")
		versions := getStringSliceFromObjArray(fieldsRaw, "versions", "name")
		description := getRawString(fieldsRaw, "description")
		epicKey := getRawKey(fieldsRaw, "epic")
		sprint := getRawString(fieldsRaw, "sprint")
		customFields := extractCustomFieldsFromRaw(it.FieldsRaw)
		out.Issues = append(out.Issues, Issue{
			ID: it.ID, Key: it.Key, Title: summary, Status: status,
			URL:     strings.TrimRight(acct.BaseURL, "/") + "/browse/" + it.Key,
			Created: created, Updated: updated,
			ResolutionDate: resolutionDate, DueDate: dueDate,
			Assignee: assignee, Reporter: reporter, Priority: priority, IssueType: issueType,
			ProjectKey: projectKey, ProjectName: projectName, Labels: labels,
			Components: components, Resolution: resolution, StatusCategory: statusCategory,
			ParentKey: parentKey, ParentID: parentID, EpicKey: epicKey, Sprint: sprint,
			FixVersions: fixVersions, Versions: versions, Description: description, CustomFields: customFields, FieldsRaw: fieldsRaw, Changelog: it.Changelog,
		})
	}
	return out, nil
}

// GetIssue fetches a single issue by key.
func (s *Service) GetIssue(ctx context.Context, in *GetIssueInput) (*GetIssueOutput, error) {
	if strings.TrimSpace(in.Key) == "" {
		return nil, errors.New("key is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	fields := normalizeJiraFields(in.Fields)
	q.Set("fields", fields)
	path := "/rest/api/3/issue/" + url.PathEscape(in.Key)
	b, err := s.jiraGET(ctx, acct, path, q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		ID        string          `json:"id"`
		Key       string          `json:"key"`
		FieldsRaw json.RawMessage `json:"fields"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, errors.New("failed to parse jira issue response")
	}
	fieldsRaw := extractFieldsFromRaw(resp.FieldsRaw)
	summary := getString(fieldsRaw, "summary")
	status := getNestedString(fieldsRaw, "status", "name")
	statusCategory := getNestedString(fieldsRaw, "status", "statusCategory", "name")
	created := getString(fieldsRaw, "created")
	updated := getString(fieldsRaw, "updated")
	resolutionDate := getString(fieldsRaw, "resolutiondate")
	dueDate := getString(fieldsRaw, "duedate")
	assignee := getNestedString(fieldsRaw, "assignee", "displayName")
	reporter := getNestedString(fieldsRaw, "reporter", "displayName")
	priority := getNestedString(fieldsRaw, "priority", "name")
	issueType := getNestedString(fieldsRaw, "issuetype", "name")
	projectKey := getNestedString(fieldsRaw, "project", "key")
	projectName := getNestedString(fieldsRaw, "project", "name")
	labels := getStringSlice(fieldsRaw, "labels")
	components := getStringSliceFromObjArray(fieldsRaw, "components", "name")
	resolution := getNestedString(fieldsRaw, "resolution", "name")
	parentKey := getNestedString(fieldsRaw, "parent", "key")
	parentID := getNestedString(fieldsRaw, "parent", "id")
	fixVersions := getStringSliceFromObjArray(fieldsRaw, "fixVersions", "name")
	versions := getStringSliceFromObjArray(fieldsRaw, "versions", "name")
	description := getRawString(fieldsRaw, "description")
	epicKey := getRawKey(fieldsRaw, "epic")
	sprint := getRawString(fieldsRaw, "sprint")
	customFields := extractCustomFieldsFromRaw(resp.FieldsRaw)
	out := &GetIssueOutput{Issue: Issue{
		ID: resp.ID, Key: resp.Key, Title: summary, Status: status,
		URL:     strings.TrimRight(acct.BaseURL, "/") + "/browse/" + resp.Key,
		Created: created, Updated: updated,
		ResolutionDate: resolutionDate, DueDate: dueDate,
		Assignee: assignee, Reporter: reporter, Priority: priority, IssueType: issueType,
		ProjectKey: projectKey, ProjectName: projectName, Labels: labels,
		Components: components, Resolution: resolution, StatusCategory: statusCategory,
		ParentKey: parentKey, ParentID: parentID, EpicKey: epicKey, Sprint: sprint,
		FixVersions: fixVersions, Versions: versions, Description: description, CustomFields: customFields, FieldsRaw: fieldsRaw,
	}}
	return out, nil
}

// UpdateIssue updates fields on an issue.
func (s *Service) UpdateIssue(ctx context.Context, in *UpdateIssueInput) (*UpdateIssueOutput, error) {
	if strings.TrimSpace(in.Key) == "" {
		return nil, errors.New("key is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	fields := map[string]any{}
	if strings.TrimSpace(in.Summary) != "" {
		fields["summary"] = in.Summary
	}
	if strings.TrimSpace(in.Description) != "" {
		fields["description"] = in.Description
	}
	if strings.TrimSpace(in.Assignee) != "" {
		fields["assignee"] = map[string]any{"accountId": in.Assignee}
	}
	if strings.TrimSpace(in.Reporter) != "" {
		fields["reporter"] = map[string]any{"accountId": in.Reporter}
	}
	if strings.TrimSpace(in.Priority) != "" {
		fields["priority"] = map[string]any{"name": in.Priority}
	}
	if len(in.Labels) > 0 {
		fields["labels"] = in.Labels
	}
	if len(in.Components) > 0 {
		var comps []map[string]any
		for _, c := range in.Components {
			if strings.TrimSpace(c) == "" {
				continue
			}
			comps = append(comps, map[string]any{"name": c})
		}
		if len(comps) > 0 {
			fields["components"] = comps
		}
	}
	if len(in.FixVersions) > 0 {
		var vers []map[string]any
		for _, v := range in.FixVersions {
			if strings.TrimSpace(v) == "" {
				continue
			}
			vers = append(vers, map[string]any{"name": v})
		}
		if len(vers) > 0 {
			fields["fixVersions"] = vers
		}
	}
	if len(in.Versions) > 0 {
		var vers []map[string]any
		for _, v := range in.Versions {
			if strings.TrimSpace(v) == "" {
				continue
			}
			vers = append(vers, map[string]any{"name": v})
		}
		if len(vers) > 0 {
			fields["versions"] = vers
		}
	}
	if strings.TrimSpace(in.DueDate) != "" {
		if _, err := time.Parse("2006-01-02", in.DueDate); err != nil {
			return nil, fmt.Errorf("invalid dueDate (expected YYYY-MM-DD): %w", err)
		}
		fields["duedate"] = in.DueDate
	}
	if strings.TrimSpace(in.ParentKey) != "" || strings.TrimSpace(in.ParentID) != "" {
		parent := map[string]any{}
		if strings.TrimSpace(in.ParentKey) != "" {
			parent["key"] = in.ParentKey
		}
		if strings.TrimSpace(in.ParentID) != "" {
			parent["id"] = in.ParentID
		}
		fields["parent"] = parent
	}
	if strings.TrimSpace(in.Resolution) != "" {
		fields["resolution"] = map[string]any{"name": in.Resolution}
	}
	if len(in.Fields) > 0 {
		for k, v := range in.Fields {
			if strings.TrimSpace(k) == "" || isZeroValue(v) {
				continue
			}
			fields[k] = v
		}
	}
	if len(in.CustomFields) > 0 {
		customFields := s.normalizeCustomFields(ctx, in.Account.Alias, in.CustomFields)
		for k, v := range customFields {
			if strings.TrimSpace(k) == "" || isZeroValue(v) {
				continue
			}
			fields[k] = v
		}
	}
	if len(fields) == 0 {
		return nil, errors.New("no fields to update")
	}
	body, _ := json.Marshal(map[string]any{"fields": fields})
	path := "/rest/api/3/issue/" + url.PathEscape(in.Key)
	_, status, err := s.jiraRequest(ctx, acct, http.MethodPut, path, "", body, "application/json")
	if err != nil {
		return nil, err
	}
	if status/100 != 2 && status != 204 {
		return nil, fmt.Errorf("jira update issue failed: %d", status)
	}
	return &UpdateIssueOutput{Updated: true}, nil
}

// TransitionIssue transitions an issue.
func (s *Service) TransitionIssue(ctx context.Context, in *TransitionIssueInput) (*TransitionIssueOutput, error) {
	if strings.TrimSpace(in.Key) == "" {
		return nil, errors.New("key is required")
	}
	if strings.TrimSpace(in.TransitionID) == "" && strings.TrimSpace(in.TransitionName) == "" {
		return nil, errors.New("transitionId or transitionName is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	transitionID := strings.TrimSpace(in.TransitionID)
	if transitionID == "" {
		// Lookup transitions by name.
		path := "/rest/api/3/issue/" + url.PathEscape(in.Key) + "/transitions"
		b, err := s.jiraGET(ctx, acct, path, "")
		if err != nil {
			return nil, err
		}
		var resp struct {
			Transitions []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"transitions"`
		}
		if err := json.Unmarshal(b, &resp); err != nil {
			return nil, errors.New("failed to parse jira transitions response")
		}
		for _, t := range resp.Transitions {
			if strings.EqualFold(t.Name, in.TransitionName) {
				transitionID = t.ID
				break
			}
		}
		if transitionID == "" {
			return nil, fmt.Errorf("transition not found: %s", in.TransitionName)
		}
	}
	fields := map[string]any{}
	if len(in.Fields) > 0 {
		for k, v := range in.Fields {
			if strings.TrimSpace(k) == "" || isZeroValue(v) {
				continue
			}
			fields[k] = v
		}
	}
	if len(in.CustomFields) > 0 {
		customFields := s.normalizeCustomFields(ctx, in.Account.Alias, in.CustomFields)
		for k, v := range customFields {
			if strings.TrimSpace(k) == "" || isZeroValue(v) {
				continue
			}
			fields[k] = v
		}
	}
	payload := map[string]any{
		"transition": map[string]any{"id": transitionID},
	}
	if len(fields) > 0 {
		payload["fields"] = fields
	}
	body, _ := json.Marshal(payload)
	path := "/rest/api/3/issue/" + url.PathEscape(in.Key) + "/transitions"
	_, status, err := s.jiraRequest(ctx, acct, http.MethodPost, path, "", body, "application/json")
	if err != nil {
		return nil, err
	}
	if status/100 != 2 && status != 204 {
		return nil, fmt.Errorf("jira transition issue failed: %d", status)
	}
	if strings.TrimSpace(in.Comment) != "" {
		_, _ = s.AddComment(ctx, &AddCommentInput{Account: in.Account, Key: in.Key, Body: in.Comment})
	}
	return &TransitionIssueOutput{Transitioned: true, TransitionID: transitionID}, nil
}

// AddWatcher adds a watcher to an issue.
func (s *Service) AddWatcher(ctx context.Context, in *AddWatcherInput) (*AddWatcherOutput, error) {
	if strings.TrimSpace(in.Key) == "" || strings.TrimSpace(in.AccountID) == "" {
		return nil, errors.New("key and accountId are required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(in.AccountID)
	path := "/rest/api/3/issue/" + url.PathEscape(in.Key) + "/watchers"
	_, status, err := s.jiraRequest(ctx, acct, http.MethodPost, path, "", body, "application/json")
	if err != nil {
		return nil, err
	}
	if status/100 != 2 && status != 204 {
		return nil, fmt.Errorf("jira add watcher failed: %d", status)
	}
	return &AddWatcherOutput{Added: true}, nil
}

// RemoveWatcher removes a watcher from an issue.
func (s *Service) RemoveWatcher(ctx context.Context, in *RemoveWatcherInput) (*RemoveWatcherOutput, error) {
	if strings.TrimSpace(in.Key) == "" || strings.TrimSpace(in.AccountID) == "" {
		return nil, errors.New("key and accountId are required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("accountId", in.AccountID)
	path := "/rest/api/3/issue/" + url.PathEscape(in.Key) + "/watchers"
	_, status, err := s.jiraRequest(ctx, acct, http.MethodDelete, path, q.Encode(), nil, "")
	if err != nil {
		return nil, err
	}
	if status/100 != 2 && status != 204 {
		return nil, fmt.Errorf("jira remove watcher failed: %d", status)
	}
	return &RemoveWatcherOutput{Removed: true}, nil
}

// ListWorklogs lists worklogs for an issue.
func (s *Service) ListWorklogs(ctx context.Context, in *ListWorklogsInput) (*ListWorklogsOutput, error) {
	if strings.TrimSpace(in.Key) == "" {
		return nil, errors.New("key is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if in.StartAt > 0 {
		q.Set("startAt", strconv.Itoa(in.StartAt))
	}
	if in.MaxResults > 0 {
		q.Set("maxResults", strconv.Itoa(in.MaxResults))
	}
	path := "/rest/api/3/issue/" + url.PathEscape(in.Key) + "/worklog"
	b, err := s.jiraGET(ctx, acct, path, q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		StartAt    int `json:"startAt"`
		MaxResults int `json:"maxResults"`
		Total      int `json:"total"`
		Worklogs   []struct {
			ID               string `json:"id"`
			Created          string `json:"created"`
			Updated          string `json:"updated"`
			Started          string `json:"started"`
			TimeSpent        string `json:"timeSpent"`
			TimeSpentSeconds int    `json:"timeSpentSeconds"`
			Comment          any    `json:"comment"`
			Author           *struct {
				DisplayName string `json:"displayName"`
			} `json:"author"`
		} `json:"worklogs"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, errors.New("failed to parse jira worklog response")
	}
	out := &ListWorklogsOutput{StartAt: resp.StartAt, MaxResults: resp.MaxResults, Total: resp.Total}
	for _, w := range resp.Worklogs {
		author := ""
		if w.Author != nil {
			author = w.Author.DisplayName
		}
		comment := ""
		if w.Comment != nil {
			if s := toString(w.Comment); s != "" {
				comment = s
			} else if b, err := json.Marshal(w.Comment); err == nil {
				comment = string(b)
			}
		}
		out.Worklogs = append(out.Worklogs, Worklog{
			ID: w.ID, Author: author, Comment: comment, Created: w.Created, Updated: w.Updated,
			Started: w.Started, TimeSpent: w.TimeSpent, TimeSpentSeconds: w.TimeSpentSeconds,
		})
	}
	return out, nil
}

// AddWorklog adds a worklog entry to an issue.
func (s *Service) AddWorklog(ctx context.Context, in *AddWorklogInput) (*AddWorklogOutput, error) {
	if strings.TrimSpace(in.Key) == "" {
		return nil, errors.New("key is required")
	}
	if strings.TrimSpace(in.TimeSpent) == "" && in.TimeSpentSeconds <= 0 {
		return nil, errors.New("timeSpent or timeSpentSeconds is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{}
	if strings.TrimSpace(in.Comment) != "" {
		payload["comment"] = in.Comment
	}
	if strings.TrimSpace(in.Started) != "" {
		payload["started"] = in.Started
	}
	if strings.TrimSpace(in.TimeSpent) != "" {
		payload["timeSpent"] = in.TimeSpent
	}
	if in.TimeSpentSeconds > 0 {
		payload["timeSpentSeconds"] = in.TimeSpentSeconds
	}
	body, _ := json.Marshal(payload)
	path := "/rest/api/3/issue/" + url.PathEscape(in.Key) + "/worklog"
	b, status, err := s.jiraRequest(ctx, acct, http.MethodPost, path, "", body, "application/json")
	if err != nil {
		return nil, err
	}
	if status/100 != 2 && status != 201 {
		return nil, fmt.Errorf("jira add worklog failed: %d", status)
	}
	var resp struct {
		ID               string `json:"id"`
		Created          string `json:"created"`
		Updated          string `json:"updated"`
		Started          string `json:"started"`
		TimeSpent        string `json:"timeSpent"`
		TimeSpentSeconds int    `json:"timeSpentSeconds"`
		Comment          any    `json:"comment"`
		Author           *struct {
			DisplayName string `json:"displayName"`
		} `json:"author"`
	}
	_ = json.Unmarshal(b, &resp)
	author := ""
	if resp.Author != nil {
		author = resp.Author.DisplayName
	}
	comment := ""
	if resp.Comment != nil {
		if s := toString(resp.Comment); s != "" {
			comment = s
		} else if b, err := json.Marshal(resp.Comment); err == nil {
			comment = string(b)
		}
	}
	return &AddWorklogOutput{Worklog: Worklog{
		ID: resp.ID, Author: author, Comment: comment, Created: resp.Created, Updated: resp.Updated,
		Started: resp.Started, TimeSpent: resp.TimeSpent, TimeSpentSeconds: resp.TimeSpentSeconds,
	}}, nil
}

// BulkCreateIssues creates issues in bulk.
func (s *Service) BulkCreateIssues(ctx context.Context, in *BulkCreateIssuesInput) (*BulkCreateIssuesOutput, error) {
	if len(in.Issues) == 0 {
		return nil, errors.New("issues are required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	var updates []map[string]any
	for _, it := range in.Issues {
		if strings.TrimSpace(it.ProjectKey) == "" || strings.TrimSpace(it.IssueType) == "" || strings.TrimSpace(it.Summary) == "" {
			return nil, errors.New("projectKey, issueType, and summary are required for each issue")
		}
		fields := map[string]any{
			"project":   map[string]any{"key": it.ProjectKey},
			"issuetype": map[string]any{"name": it.IssueType},
			"summary":   it.Summary,
		}
		if strings.TrimSpace(it.Description) != "" {
			fields["description"] = it.Description
		}
		if strings.TrimSpace(it.Assignee) != "" {
			fields["assignee"] = map[string]any{"accountId": it.Assignee}
		}
		if strings.TrimSpace(it.Reporter) != "" {
			fields["reporter"] = map[string]any{"accountId": it.Reporter}
		}
		if strings.TrimSpace(it.Priority) != "" {
			fields["priority"] = map[string]any{"name": it.Priority}
		}
		if len(it.Labels) > 0 {
			fields["labels"] = it.Labels
		}
		if len(it.Components) > 0 {
			var comps []map[string]any
			for _, c := range it.Components {
				if strings.TrimSpace(c) == "" {
					continue
				}
				comps = append(comps, map[string]any{"name": c})
			}
			if len(comps) > 0 {
				fields["components"] = comps
			}
		}
		if len(it.FixVersions) > 0 {
			var vers []map[string]any
			for _, v := range it.FixVersions {
				if strings.TrimSpace(v) == "" {
					continue
				}
				vers = append(vers, map[string]any{"name": v})
			}
			if len(vers) > 0 {
				fields["fixVersions"] = vers
			}
		}
		if len(it.Versions) > 0 {
			var vers []map[string]any
			for _, v := range it.Versions {
				if strings.TrimSpace(v) == "" {
					continue
				}
				vers = append(vers, map[string]any{"name": v})
			}
			if len(vers) > 0 {
				fields["versions"] = vers
			}
		}
		if strings.TrimSpace(it.DueDate) != "" {
			if _, err := time.Parse("2006-01-02", it.DueDate); err != nil {
				return nil, fmt.Errorf("invalid dueDate (expected YYYY-MM-DD): %w", err)
			}
			fields["duedate"] = it.DueDate
		}
		if strings.TrimSpace(it.ParentKey) != "" || strings.TrimSpace(it.ParentID) != "" {
			parent := map[string]any{}
			if strings.TrimSpace(it.ParentKey) != "" {
				parent["key"] = it.ParentKey
			}
			if strings.TrimSpace(it.ParentID) != "" {
				parent["id"] = it.ParentID
			}
			fields["parent"] = parent
		}
		if strings.TrimSpace(it.Resolution) != "" {
			fields["resolution"] = map[string]any{"name": it.Resolution}
		}
		if len(it.CustomFields) > 0 {
			customFields := s.normalizeCustomFields(ctx, in.Account.Alias, it.CustomFields)
			if len(customFields) > 0 {
				if meta, err := s.CreateMeta(ctx, &CreateMetaInput{Account: in.Account, ProjectKey: it.ProjectKey, IssueType: it.IssueType}); err == nil {
					customFields = normalizeCustomFieldsWithMeta(customFields, meta)
				}
			}
			for k, v := range customFields {
				if strings.TrimSpace(k) == "" || isZeroValue(v) {
					continue
				}
				fields[k] = v
			}
		}
		updates = append(updates, map[string]any{"fields": fields})
	}
	body, _ := json.Marshal(map[string]any{"issueUpdates": updates})
	b, _, err := s.jiraRequest(ctx, acct, http.MethodPost, "/rest/api/3/issue/bulk", "", body, "application/json")
	if err != nil {
		return nil, err
	}
	return &BulkCreateIssuesOutput{Raw: json.RawMessage(b)}, nil
}

// BulkUpdateIssues updates issues in bulk.
func (s *Service) BulkUpdateIssues(ctx context.Context, in *BulkUpdateIssuesInput) (*BulkUpdateIssuesOutput, error) {
	if len(in.Issues) == 0 {
		return nil, errors.New("issues are required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	var updates []map[string]any
	for _, it := range in.Issues {
		if strings.TrimSpace(it.Key) == "" && strings.TrimSpace(it.ID) == "" {
			return nil, errors.New("key or id is required for each issue")
		}
		entry := map[string]any{}
		if strings.TrimSpace(it.Key) != "" {
			entry["key"] = it.Key
		}
		if strings.TrimSpace(it.ID) != "" {
			entry["id"] = it.ID
		}
		fields := map[string]any{}
		for k, v := range it.Fields {
			if strings.TrimSpace(k) == "" || isZeroValue(v) {
				continue
			}
			fields[k] = v
		}
		if len(it.CustomFields) > 0 {
			customFields := s.normalizeCustomFields(ctx, in.Account.Alias, it.CustomFields)
			for k, v := range customFields {
				if strings.TrimSpace(k) == "" || isZeroValue(v) {
					continue
				}
				fields[k] = v
			}
		}
		if len(fields) > 0 {
			entry["fields"] = fields
		}
		updates = append(updates, entry)
	}
	body, _ := json.Marshal(map[string]any{"issueUpdates": updates})
	b, _, err := s.jiraRequest(ctx, acct, http.MethodPut, "/rest/api/3/issue/bulk", "", body, "application/json")
	if err != nil {
		return nil, err
	}
	return &BulkUpdateIssuesOutput{Raw: json.RawMessage(b)}, nil
}

// DeleteIssue deletes an issue.
func (s *Service) DeleteIssue(ctx context.Context, in *DeleteIssueInput) (*DeleteIssueOutput, error) {
	if strings.TrimSpace(in.Key) == "" {
		return nil, errors.New("key is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if in.DeleteSubtasks {
		q.Set("deleteSubtasks", "true")
	}
	path := "/rest/api/3/issue/" + url.PathEscape(in.Key)
	_, status, err := s.jiraRequest(ctx, acct, http.MethodDelete, path, q.Encode(), nil, "")
	if err != nil {
		return nil, err
	}
	if status/100 != 2 && status != 204 {
		return nil, fmt.Errorf("jira delete issue failed: %d", status)
	}
	return &DeleteIssueOutput{Deleted: true}, nil
}

func buildJQL(in *SearchIssuesInput) string {
	var parts []string
	if strings.TrimSpace(in.ProjectKey) != "" {
		parts = append(parts, "project = "+strings.TrimSpace(in.ProjectKey))
	}
	if strings.TrimSpace(in.CreatedFrom) != "" {
		parts = append(parts, fmt.Sprintf("created >= \"%s\"", strings.TrimSpace(in.CreatedFrom)))
	}
	if strings.TrimSpace(in.CreatedTo) != "" {
		parts = append(parts, fmt.Sprintf("created <= \"%s\"", strings.TrimSpace(in.CreatedTo)))
	}
	if strings.TrimSpace(in.UpdatedFrom) != "" {
		parts = append(parts, fmt.Sprintf("updated >= \"%s\"", strings.TrimSpace(in.UpdatedFrom)))
	}
	if strings.TrimSpace(in.UpdatedTo) != "" {
		parts = append(parts, fmt.Sprintf("updated <= \"%s\"", strings.TrimSpace(in.UpdatedTo)))
	}
	if len(parts) == 0 {
		return ""
	}
	jql := strings.Join(parts, " AND ")
	if strings.TrimSpace(in.OrderBy) != "" {
		jql += " ORDER BY " + strings.TrimSpace(in.OrderBy)
	}
	return jql
}

func normalizeJiraFields(fields []string) string {
	if len(fields) == 0 {
		return "*all"
	}
	seen := map[string]struct{}{}
	var out []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if f == "*all" {
			return "*all"
		}
		key := strings.ToLower(f)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	if len(out) == 0 {
		return "summary,status,created,updated,resolutiondate,duedate,assignee,reporter,priority,issuetype,project,labels,components,resolution,parent,fixVersions,versions,description,sprint,epic"
	}
	return strings.Join(out, ",")
}

func splitFieldList(fields string) []string {
	fields = strings.TrimSpace(fields)
	if fields == "" {
		return nil
	}
	if fields == "*all" {
		return []string{"*all"}
	}
	parts := strings.Split(fields, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// CreateMeta fetches issue create metadata for a project and issue type.
func (s *Service) CreateMeta(ctx context.Context, in *CreateMetaInput) (*CreateMetaOutput, error) {
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if strings.TrimSpace(in.ProjectKey) != "" {
		q.Set("projectKeys", in.ProjectKey)
	}
	if strings.TrimSpace(in.IssueType) != "" {
		q.Set("issuetypeNames", in.IssueType)
	}
	expand := strings.TrimSpace(in.Expand)
	if expand == "" {
		expand = "projects.issuetypes.fields"
	}
	q.Set("expand", expand)
	b, err := s.jiraGET(ctx, acct, "/rest/api/3/issue/createmeta", q.Encode())
	if err != nil {
		return nil, err
	}
	return &CreateMetaOutput{Raw: json.RawMessage(b)}, nil
}

// ListSprints lists sprints for a board (Agile API).
func (s *Service) ListSprints(ctx context.Context, in *ListSprintsInput) (*ListSprintsOutput, error) {
	if in.BoardID <= 0 {
		return nil, errors.New("boardId is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if strings.TrimSpace(in.State) != "" {
		q.Set("state", strings.TrimSpace(in.State))
	}
	if in.StartAt > 0 {
		q.Set("startAt", strconv.Itoa(in.StartAt))
	}
	if in.MaxResults > 0 {
		q.Set("maxResults", strconv.Itoa(in.MaxResults))
	}
	path := "/rest/agile/1.0/board/" + strconv.Itoa(in.BoardID) + "/sprint"
	b, err := s.jiraGET(ctx, acct, path, q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		StartAt    int  `json:"startAt"`
		MaxResults int  `json:"maxResults"`
		Total      int  `json:"total"`
		IsLast     bool `json:"isLast"`
		Values     []struct {
			ID           int    `json:"id"`
			Name         string `json:"name"`
			State        string `json:"state"`
			StartDate    string `json:"startDate"`
			EndDate      string `json:"endDate"`
			CompleteDate string `json:"completeDate"`
		} `json:"values"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, err
	}
	out := &ListSprintsOutput{
		StartAt:    resp.StartAt,
		MaxResults: resp.MaxResults,
		Total:      resp.Total,
		IsLast:     resp.IsLast,
	}
	for _, v := range resp.Values {
		out.Sprints = append(out.Sprints, Sprint{
			ID:           v.ID,
			Name:         v.Name,
			State:        v.State,
			StartDate:    v.StartDate,
			EndDate:      v.EndDate,
			CompleteDate: v.CompleteDate,
		})
	}
	return out, nil
}

// GetActiveSprint returns the first active sprint for a board.
func (s *Service) GetActiveSprint(ctx context.Context, in *GetActiveSprintInput) (*GetActiveSprintOutput, error) {
	if in.BoardID <= 0 {
		return nil, errors.New("boardId is required")
	}
	out, err := s.ListSprints(ctx, &ListSprintsInput{
		Account:    in.Account,
		BoardID:    in.BoardID,
		State:      "active",
		MaxResults: 1,
	})
	if err != nil {
		return nil, err
	}
	if out == nil || len(out.Sprints) == 0 {
		return nil, errors.New("no active sprint found")
	}
	return &GetActiveSprintOutput{Sprint: out.Sprints[0]}, nil
}

// ListSprintIssues lists issues for a sprint (Agile API).
func (s *Service) ListSprintIssues(ctx context.Context, in *ListSprintIssuesInput) (*ListSprintIssuesOutput, error) {
	if in.SprintID <= 0 {
		return nil, errors.New("sprintId is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if strings.TrimSpace(in.JQL) != "" {
		q.Set("jql", strings.TrimSpace(in.JQL))
	}
	fields := normalizeJiraFields(splitFieldList(in.Fields))
	q.Set("fields", fields)
	if in.StartAt > 0 {
		q.Set("startAt", strconv.Itoa(in.StartAt))
	}
	if in.MaxResults > 0 {
		q.Set("maxResults", strconv.Itoa(in.MaxResults))
	}
	path := "/rest/agile/1.0/sprint/" + strconv.Itoa(in.SprintID) + "/issue"
	b, err := s.jiraGET(ctx, acct, path, q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		StartAt    int  `json:"startAt"`
		MaxResults int  `json:"maxResults"`
		Total      int  `json:"total"`
		IsLast     bool `json:"isLast"`
		Issues     []struct {
			ID        string          `json:"id"`
			Key       string          `json:"key"`
			FieldsRaw json.RawMessage `json:"fields"`
		} `json:"issues"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		return nil, err
	}
	out := &ListSprintIssuesOutput{
		StartAt:    resp.StartAt,
		MaxResults: resp.MaxResults,
		Total:      resp.Total,
		IsLast:     resp.IsLast,
	}
	for _, it := range resp.Issues {
		fieldsRaw := extractFieldsFromRaw(it.FieldsRaw)
		summary := getString(fieldsRaw, "summary")
		status := getNestedString(fieldsRaw, "status", "name")
		statusCategory := getNestedString(fieldsRaw, "status", "statusCategory", "name")
		created := getString(fieldsRaw, "created")
		updated := getString(fieldsRaw, "updated")
		resolutionDate := getString(fieldsRaw, "resolutiondate")
		dueDate := getString(fieldsRaw, "duedate")
		assignee := getNestedString(fieldsRaw, "assignee", "displayName")
		reporter := getNestedString(fieldsRaw, "reporter", "displayName")
		priority := getNestedString(fieldsRaw, "priority", "name")
		issueType := getNestedString(fieldsRaw, "issuetype", "name")
		projectKey := getNestedString(fieldsRaw, "project", "key")
		projectName := getNestedString(fieldsRaw, "project", "name")
		labels := getStringSlice(fieldsRaw, "labels")
		components := getStringSliceFromObjArray(fieldsRaw, "components", "name")
		resolution := getNestedString(fieldsRaw, "resolution", "name")
		parentKey := getNestedString(fieldsRaw, "parent", "key")
		parentID := getNestedString(fieldsRaw, "parent", "id")
		fixVersions := getStringSliceFromObjArray(fieldsRaw, "fixVersions", "name")
		versions := getStringSliceFromObjArray(fieldsRaw, "versions", "name")
		description := getRawString(fieldsRaw, "description")
		epicKey := getRawKey(fieldsRaw, "epic")
		sprint := getRawString(fieldsRaw, "sprint")
		customFields := extractCustomFieldsFromRaw(it.FieldsRaw)
		out.Issues = append(out.Issues, Issue{
			ID: it.ID, Key: it.Key, Title: summary, Status: status,
			URL:     strings.TrimRight(acct.BaseURL, "/") + "/browse/" + it.Key,
			Created: created, Updated: updated,
			ResolutionDate: resolutionDate, DueDate: dueDate,
			Assignee: assignee, Reporter: reporter, Priority: priority, IssueType: issueType,
			ProjectKey: projectKey, ProjectName: projectName, Labels: labels,
			Components: components, Resolution: resolution, StatusCategory: statusCategory,
			ParentKey: parentKey, ParentID: parentID, EpicKey: epicKey, Sprint: sprint,
			FixVersions: fixVersions, Versions: versions, Description: description, CustomFields: customFields, FieldsRaw: fieldsRaw,
		})
	}
	return out, nil
}

// ListCustomFieldContexts lists contexts for a custom field.
func (s *Service) ListCustomFieldContexts(ctx context.Context, in *ListCustomFieldContextsInput) (*ListCustomFieldContextsOutput, error) {
	if strings.TrimSpace(in.FieldID) == "" {
		return nil, errors.New("fieldId is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	path := "/rest/api/3/field/" + url.PathEscape(in.FieldID) + "/context"
	b, err := s.jiraGET(ctx, acct, path, "")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Values []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"values"`
	}
	_ = json.Unmarshal(b, &resp)
	out := &ListCustomFieldContextsOutput{}
	for _, v := range resp.Values {
		out.Contexts = append(out.Contexts, CustomFieldContext{ID: v.ID, Name: v.Name})
	}
	return out, nil
}

// ListCustomFieldOptions lists options for a custom field context.
func (s *Service) ListCustomFieldOptions(ctx context.Context, in *ListCustomFieldOptionsInput) (*ListCustomFieldOptionsOutput, error) {
	if strings.TrimSpace(in.FieldID) == "" || strings.TrimSpace(in.ContextID) == "" {
		return nil, errors.New("fieldId and contextId are required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	if in.StartAt > 0 {
		q.Set("startAt", strconv.Itoa(in.StartAt))
	}
	if in.MaxResults > 0 {
		q.Set("maxResults", strconv.Itoa(in.MaxResults))
	}
	path := "/rest/api/3/field/" + url.PathEscape(in.FieldID) + "/context/" + url.PathEscape(in.ContextID) + "/option"
	b, err := s.jiraGET(ctx, acct, path, q.Encode())
	if err != nil {
		return nil, err
	}
	var resp struct {
		IsLast     bool `json:"isLast"`
		StartAt    int  `json:"startAt"`
		MaxResults int  `json:"maxResults"`
		Total      int  `json:"total"`
		Values     []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
			Name  string `json:"name"`
		} `json:"values"`
	}
	_ = json.Unmarshal(b, &resp)
	out := &ListCustomFieldOptionsOutput{
		IsLast:     resp.IsLast,
		StartAt:    resp.StartAt,
		MaxResults: resp.MaxResults,
		Total:      resp.Total,
	}
	for _, v := range resp.Values {
		out.Options = append(out.Options, CustomFieldOption{ID: v.ID, Value: v.Value, Name: v.Name})
	}
	return out, nil
}

// ListUsers searches Jira users by query.
func (s *Service) ListUsers(ctx context.Context, in *ListUsersInput) (*ListUsersOutput, error) {
	if strings.TrimSpace(in.Query) == "" {
		return nil, errors.New("query is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("query", in.Query)
	if in.StartAt > 0 {
		q.Set("startAt", strconv.Itoa(in.StartAt))
	}
	if in.MaxResults > 0 {
		q.Set("maxResults", strconv.Itoa(in.MaxResults))
	}
	b, err := s.jiraGET(ctx, acct, "/rest/api/3/user/search", q.Encode())
	if err != nil {
		return nil, err
	}
	var resp []struct {
		AccountID   string `json:"accountId"`
		DisplayName string `json:"displayName"`
		Email       string `json:"emailAddress"`
		Active      bool   `json:"active"`
	}
	_ = json.Unmarshal(b, &resp)
	out := &ListUsersOutput{}
	for _, u := range resp {
		out.Users = append(out.Users, User{
			AccountID:   u.AccountID,
			DisplayName: u.DisplayName,
			Email:       u.Email,
			Active:      u.Active,
		})
	}
	return out, nil
}

func jsonRawToString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

func jsonRawToKey(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var obj struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Key
	}
	return ""
}

func extractCustomFieldsFromUnknowns(m tcontainer.MarshalMap) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for k, v := range m {
		if strings.HasPrefix(k, "customfield_") {
			if isZeroValue(v) {
				continue
			}
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func extractFieldsFromUnknowns(m tcontainer.MarshalMap) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func extractCustomFieldsFromRaw(raw json.RawMessage) map[string]any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range fields {
		if strings.HasPrefix(k, "customfield_") {
			if isZeroValue(v) {
				continue
			}
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func extractFieldsFromRaw(raw json.RawMessage) map[string]any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	if len(fields) == 0 {
		return nil
	}
	return fields
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	return toString(m[key])
}

func getNestedString(m map[string]any, keys ...string) string {
	if m == nil {
		return ""
	}
	var cur any = m
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	return toString(cur)
}

func getStringSlice(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	return toStringSlice(m[key])
}

func getStringSliceFromObjArray(m map[string]any, key, field string) []string {
	if m == nil {
		return nil
	}
	arr, ok := m[key].([]any)
	if !ok || len(arr) == 0 {
		return nil
	}
	var out []string
	for _, it := range arr {
		obj, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if s := toString(obj[field]); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func getRawString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if m[key] == nil {
		return ""
	}
	b, err := json.Marshal(m[key])
	if err != nil {
		return ""
	}
	return string(b)
}

func getRawKey(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	obj, ok := m[key].(map[string]any)
	if !ok {
		return ""
	}
	if v, ok := obj["key"]; ok {
		return toString(v)
	}
	return ""
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		var out []string
		for _, it := range t {
			if s := toString(it); s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return nil
	}
}

func jiraTimeString(t jira.Time) string {
	tt := time.Time(t)
	if tt.IsZero() {
		return ""
	}
	return tt.Format(time.RFC3339)
}

func jiraDateString(d jira.Date) string {
	tt := time.Time(d)
	if tt.IsZero() {
		return ""
	}
	return tt.Format("2006-01-02")
}

func isZeroValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.String:
		return strings.TrimSpace(rv.String()) == ""
	case reflect.Slice, reflect.Map, reflect.Array:
		return rv.Len() == 0
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			return true
		}
		return isZeroValue(rv.Elem().Interface())
	}
	zero := reflect.Zero(rv.Type())
	return reflect.DeepEqual(rv.Interface(), zero.Interface())
}

func (s *Service) normalizeCustomFields(ctx context.Context, alias string, in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	cache := map[string]string{}
	out := map[string]any{}
	for k, v := range in {
		if strings.TrimSpace(k) == "" {
			continue
		}
		if isZeroValue(v) {
			continue
		}
		nv := s.normalizeCustomFieldValue(ctx, alias, k, v, cache)
		if isZeroValue(nv) {
			continue
		}
		out[k] = nv
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Service) normalizeCustomFieldValue(ctx context.Context, alias, fieldID string, v any, cache map[string]string) any {
	if !strings.HasPrefix(fieldID, "customfield_") {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		if id, ok := t["id"]; ok {
			idStr := strings.TrimSpace(toString(id))
			if idStr == "" {
				return nil
			}
			return map[string]any{"id": idStr}
		}
		if name, ok := t["name"]; ok {
			nameStr := strings.TrimSpace(toString(name))
			if nameStr == "" {
				return nil
			}
			if id := s.resolveCustomFieldOptionID(ctx, alias, fieldID, nameStr, cache); id != "" {
				return map[string]any{"id": id}
			}
			return t
		}
		if value, ok := t["value"]; ok {
			valStr := strings.TrimSpace(toString(value))
			if valStr == "" {
				return nil
			}
			if id := s.resolveCustomFieldOptionID(ctx, alias, fieldID, valStr, cache); id != "" {
				return map[string]any{"id": id}
			}
			return t
		}
		return t
	case map[string]string:
		if id, ok := t["id"]; ok {
			idStr := strings.TrimSpace(id)
			if idStr == "" {
				return nil
			}
			return map[string]any{"id": idStr}
		}
		if name, ok := t["name"]; ok {
			nameStr := strings.TrimSpace(name)
			if nameStr == "" {
				return nil
			}
			if id := s.resolveCustomFieldOptionID(ctx, alias, fieldID, nameStr, cache); id != "" {
				return map[string]any{"id": id}
			}
			return map[string]any{"name": nameStr}
		}
		if value, ok := t["value"]; ok {
			valStr := strings.TrimSpace(value)
			if valStr == "" {
				return nil
			}
			if id := s.resolveCustomFieldOptionID(ctx, alias, fieldID, valStr, cache); id != "" {
				return map[string]any{"id": id}
			}
			return map[string]any{"value": valStr}
		}
		out := map[string]any{}
		for k, v := range t {
			out[k] = v
		}
		return out
	case []string:
		var out []any
		for _, it := range t {
			nv := s.normalizeCustomFieldValue(ctx, alias, fieldID, it, cache)
			if isZeroValue(nv) {
				continue
			}
			out = append(out, nv)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		var out []any
		for _, it := range t {
			nv := s.normalizeCustomFieldValue(ctx, alias, fieldID, it, cache)
			if isZeroValue(nv) {
				continue
			}
			out = append(out, nv)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case string:
		val := strings.TrimSpace(t)
		if val == "" {
			return ""
		}
		if id := s.resolveCustomFieldOptionID(ctx, alias, fieldID, val, cache); id != "" {
			return map[string]any{"id": id}
		}
		return val
	default:
		return v
	}
}

func (s *Service) resolveCustomFieldOptionID(ctx context.Context, alias, fieldID, name string, cache map[string]string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if cache == nil {
		cache = map[string]string{}
	}
	cacheKey := strings.ToLower(fieldID + "|" + name)
	if v, ok := cache[cacheKey]; ok {
		return v
	}
	ctxs, err := s.ListCustomFieldContexts(ctx, &ListCustomFieldContextsInput{
		Account: AccountRef{Alias: alias},
		FieldID: fieldID,
	})
	if err != nil {
		cache[cacheKey] = ""
		return ""
	}
	target := strings.TrimSpace(name)
	for _, c := range ctxs.Contexts {
		startAt := 0
		for {
			opts, err := s.ListCustomFieldOptions(ctx, &ListCustomFieldOptionsInput{
				Account:    AccountRef{Alias: alias},
				FieldID:    fieldID,
				ContextID:  c.ID,
				StartAt:    startAt,
				MaxResults: 100,
			})
			if err != nil {
				break
			}
			for _, o := range opts.Options {
				if strings.EqualFold(strings.TrimSpace(o.Value), target) || strings.EqualFold(strings.TrimSpace(o.Name), target) {
					cache[cacheKey] = o.ID
					return o.ID
				}
			}
			if opts.IsLast || len(opts.Options) == 0 {
				break
			}
			if opts.MaxResults > 0 {
				startAt += opts.MaxResults
			} else {
				startAt += len(opts.Options)
			}
		}
	}
	cache[cacheKey] = ""
	return ""
}

type createMetaField struct {
	AllowedValues []map[string]any `json:"allowedValues"`
}

type createMetaIssueType struct {
	Fields map[string]createMetaField `json:"fields"`
}

type createMetaProject struct {
	IssueTypes []createMetaIssueType `json:"issuetypes"`
}

type createMetaResponse struct {
	Projects []createMetaProject `json:"projects"`
}

func buildAllowedValueLookup(meta *CreateMetaOutput) map[string]map[string]string {
	if meta == nil || len(meta.Raw) == 0 {
		return nil
	}
	var resp createMetaResponse
	if err := json.Unmarshal(meta.Raw, &resp); err != nil {
		return nil
	}
	lookup := map[string]map[string]string{}
	for _, p := range resp.Projects {
		for _, it := range p.IssueTypes {
			for fieldID, field := range it.Fields {
				if len(field.AllowedValues) == 0 {
					continue
				}
				m := lookup[fieldID]
				if m == nil {
					m = map[string]string{}
					lookup[fieldID] = m
				}
				for _, av := range field.AllowedValues {
					id := strings.TrimSpace(toString(av["id"]))
					if id == "" {
						continue
					}
					if v := strings.TrimSpace(toString(av["value"])); v != "" {
						m[strings.ToLower(v)] = id
					}
					if n := strings.TrimSpace(toString(av["name"])); n != "" {
						m[strings.ToLower(n)] = id
					}
				}
			}
		}
	}
	if len(lookup) == 0 {
		return nil
	}
	return lookup
}

func normalizeCustomFieldValueWithLookup(fieldID string, v any, lookup map[string]map[string]string) any {
	if !strings.HasPrefix(fieldID, "customfield_") {
		return v
	}
	fieldLookup := lookup[fieldID]
	resolve := func(raw any) string {
		if fieldLookup == nil {
			return ""
		}
		key := strings.ToLower(strings.TrimSpace(toString(raw)))
		if key == "" {
			return ""
		}
		return fieldLookup[key]
	}
	switch t := v.(type) {
	case map[string]any:
		if id, ok := t["id"]; ok {
			idStr := strings.TrimSpace(toString(id))
			if idStr == "" {
				return nil
			}
			return map[string]any{"id": idStr}
		}
		if name, ok := t["name"]; ok {
			if id := resolve(name); id != "" {
				return map[string]any{"id": id}
			}
			return map[string]any{"name": strings.TrimSpace(toString(name))}
		}
		if value, ok := t["value"]; ok {
			if id := resolve(value); id != "" {
				return map[string]any{"id": id}
			}
			return map[string]any{"value": strings.TrimSpace(toString(value))}
		}
		return t
	case map[string]string:
		if id, ok := t["id"]; ok {
			idStr := strings.TrimSpace(id)
			if idStr == "" {
				return nil
			}
			return map[string]any{"id": idStr}
		}
		if name, ok := t["name"]; ok {
			if id := resolve(name); id != "" {
				return map[string]any{"id": id}
			}
			return map[string]any{"name": strings.TrimSpace(name)}
		}
		if value, ok := t["value"]; ok {
			if id := resolve(value); id != "" {
				return map[string]any{"id": id}
			}
			return map[string]any{"value": strings.TrimSpace(value)}
		}
		out := map[string]any{}
		for k, v := range t {
			out[k] = v
		}
		return out
	case []string:
		var out []any
		for _, it := range t {
			nv := normalizeCustomFieldValueWithLookup(fieldID, it, lookup)
			if isZeroValue(nv) {
				continue
			}
			out = append(out, nv)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case []any:
		var out []any
		for _, it := range t {
			nv := normalizeCustomFieldValueWithLookup(fieldID, it, lookup)
			if isZeroValue(nv) {
				continue
			}
			out = append(out, nv)
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case string:
		if id := resolve(t); id != "" {
			return map[string]any{"id": id}
		}
		return strings.TrimSpace(t)
	default:
		return v
	}
}

func normalizeCustomFieldsWithMeta(in map[string]any, meta *CreateMetaOutput) map[string]any {
	if len(in) == 0 || meta == nil {
		return in
	}
	lookup := buildAllowedValueLookup(meta)
	if len(lookup) == 0 {
		return in
	}
	out := map[string]any{}
	for k, v := range in {
		if strings.TrimSpace(k) == "" || isZeroValue(v) {
			continue
		}
		nv := normalizeCustomFieldValueWithLookup(k, v, lookup)
		if isZeroValue(nv) {
			continue
		}
		out[k] = nv
	}
	if len(out) == 0 {
		return in
	}
	return out
}

// CreateIssue creates a new issue.
func (s *Service) CreateIssue(ctx context.Context, in *CreateIssueInput) (*CreateIssueOutput, error) {
	if in.ProjectKey == "" || in.IssueType == "" || strings.TrimSpace(in.Summary) == "" {
		return nil, errors.New("projectKey, issueType, and summary are required")
	}
	cli, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	payload := &jira.Issue{
		Fields: &jira.IssueFields{
			Type:        jira.IssueType{Name: in.IssueType},
			Project:     jira.Project{Key: in.ProjectKey},
			Summary:     in.Summary,
			Description: in.Description,
		},
	}
	fields := payload.Fields
	if in.Assignee != "" {
		fields.Assignee = &jira.User{AccountID: in.Assignee, Name: in.Assignee}
	}
	if in.Reporter != "" {
		fields.Reporter = &jira.User{AccountID: in.Reporter, Name: in.Reporter}
	}
	if in.Priority != "" {
		fields.Priority = &jira.Priority{Name: in.Priority}
	}
	if len(in.Labels) > 0 {
		fields.Labels = append([]string{}, in.Labels...)
	}
	if len(in.Components) > 0 {
		for _, c := range in.Components {
			if strings.TrimSpace(c) == "" {
				continue
			}
			fields.Components = append(fields.Components, &jira.Component{Name: c})
		}
	}
	if len(in.FixVersions) > 0 {
		for _, v := range in.FixVersions {
			if strings.TrimSpace(v) == "" {
				continue
			}
			fields.FixVersions = append(fields.FixVersions, &jira.FixVersion{Name: v})
		}
	}
	if len(in.Versions) > 0 {
		for _, v := range in.Versions {
			if strings.TrimSpace(v) == "" {
				continue
			}
			fields.AffectsVersions = append(fields.AffectsVersions, &jira.AffectsVersion{Name: v})
		}
	}
	if in.DueDate != "" {
		dt, err := time.Parse("2006-01-02", in.DueDate)
		if err != nil {
			return nil, fmt.Errorf("invalid dueDate (expected YYYY-MM-DD): %w", err)
		}
		fields.Duedate = jira.Date(dt)
	}
	if in.ParentKey != "" || in.ParentID != "" {
		fields.Parent = &jira.Parent{Key: in.ParentKey, ID: in.ParentID}
	}
	if in.Resolution != "" {
		fields.Resolution = &jira.Resolution{Name: in.Resolution}
	}
	if len(in.CustomFields) > 0 {
		customFields := s.normalizeCustomFields(ctx, in.Account.Alias, in.CustomFields)
		if len(customFields) > 0 {
			if meta, err := s.CreateMeta(ctx, &CreateMetaInput{
				Account:    in.Account,
				ProjectKey: in.ProjectKey,
				IssueType:  in.IssueType,
			}); err == nil {
				customFields = normalizeCustomFieldsWithMeta(customFields, meta)
			}
		}
		if len(customFields) > 0 {
			fields.Unknowns = tcontainer.NewMarshalMap()
			for k, v := range customFields {
				if strings.TrimSpace(k) == "" {
					continue
				}
				if isZeroValue(v) {
					continue
				}
				fields.Unknowns[k] = v
			}
		}
	}
	created, resp, err := cli.Issue.CreateWithContext(ctx, payload)
	if err != nil {
		if resp != nil && resp.Body != nil {
			if b, rerr := io.ReadAll(resp.Body); rerr == nil && len(b) > 0 {
				return nil, fmt.Errorf("create issue failed: %w: %s", err, strings.TrimSpace(string(b)))
			}
		}
		return nil, err
	}
	out := &CreateIssueOutput{Issue: Issue{ID: created.ID, Key: created.Key, Title: in.Summary}}
	out.Issue.URL = strings.TrimRight(acct.BaseURL, "/") + "/browse/" + created.Key
	return out, nil
}

// AddComment adds a comment to the issue.
func (s *Service) AddComment(ctx context.Context, in *AddCommentInput) (*AddCommentOutput, error) {
	if in.Key == "" || strings.TrimSpace(in.Body) == "" {
		return nil, errors.New("key and body are required")
	}
	cli, _, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	c := &jira.Comment{Body: in.Body}
	added, _, err := cli.Issue.AddComment(in.Key, c)
	if err != nil {
		return nil, err
	}
	return &AddCommentOutput{ID: added.ID}, nil
}

// ListComments lists comments for an issue.
func (s *Service) ListComments(ctx context.Context, in *ListCommentsInput) (*ListCommentsOutput, error) {
	if in.Key == "" {
		return nil, errors.New("key is required")
	}
	_, acct, err := s.client(ctx, in.Account.Alias)
	if err != nil {
		return nil, err
	}
	// REST fallback: GET /rest/api/2/issue/{key}/comment
	b, err := s.jiraGET(ctx, acct, "/rest/api/2/issue/"+url.PathEscape(in.Key)+"/comment", "")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Comments []struct {
			ID     string `json:"id"`
			Body   string `json:"body"`
			Author *struct {
				DisplayName string `json:"displayName"`
			} `json:"author"`
		} `json:"comments"`
	}
	_ = json.Unmarshal(b, &resp)
	out := &ListCommentsOutput{}
	for _, c := range resp.Comments {
		author := ""
		if c.Author != nil {
			author = c.Author.DisplayName
		}
		out.Comments = append(out.Comments, Comment{ID: c.ID, Body: c.Body, Author: author})
	}
	return out, nil
}

// jiraGET performs basic auth GET using account credentials.
func (s *Service) jiraGET(ctx context.Context, acct Account, path, query string) ([]byte, error) {
	base := strings.TrimRight(acct.BaseURL, "/")
	u := base + path
	if query != "" {
		u += "?" + query
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	req.SetBasicAuth(acct.Email, acct.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("jira get %s failed: %s", path, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

// jiraRequest performs a Jira REST request with basic auth.
func (s *Service) jiraRequest(ctx context.Context, acct Account, method, path, query string, body []byte, contentType string) ([]byte, int, error) {
	base := strings.TrimRight(acct.BaseURL, "/")
	u := base + path
	if query != "" {
		u += "?" + query
	}
	var reader io.Reader
	if len(body) > 0 {
		reader = strings.NewReader(string(body))
	}
	req, _ := http.NewRequestWithContext(ctx, method, u, reader)
	req.SetBasicAuth(acct.Email, acct.Token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 && resp.StatusCode != 204 {
		msg := strings.TrimSpace(string(b))
		if msg != "" {
			return b, resp.StatusCode, fmt.Errorf("jira %s %s failed: %s", method, path, msg)
		}
		return b, resp.StatusCode, fmt.Errorf("jira %s %s failed: %s", method, path, resp.Status)
	}
	return b, resp.StatusCode, nil
}
