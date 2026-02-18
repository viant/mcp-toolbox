package service

import "encoding/json"

// Common input/output types for Jira tools.

type AccountRef struct {
	// Alias selects configured account; when empty, "default" is used.
	Alias string `json:"alias,omitempty"`
}

// ListProjectsInput lists accessible projects.
type ListProjectsInput struct {
	Account AccountRef `json:"account"`
}

type Project struct {
	ID   string `json:"id"`
	Key  string `json:"key"`
	Name string `json:"name"`
}

type ListProjectsOutput struct {
	Projects []Project `json:"projects"`
}

// SearchIssuesInput executes a JQL query.
type SearchIssuesInput struct {
	Account          AccountRef `json:"account"`
	JQL              string     `json:"jql"`
	ProjectKey       string     `json:"projectKey,omitempty"`
	CreatedFrom      string     `json:"createdFrom,omitempty"` // e.g. 2026-02-01 or 2026-02-01 10:00
	CreatedTo        string     `json:"createdTo,omitempty"`
	UpdatedFrom      string     `json:"updatedFrom,omitempty"`
	UpdatedTo        string     `json:"updatedTo,omitempty"`
	OrderBy          string     `json:"orderBy,omitempty"` // e.g. updated DESC
	Fields           []string   `json:"fields,omitempty"`
	IncludeChangelog bool       `json:"includeChangelog,omitempty"`
	MaxResults       int        `json:"maxResults,omitempty"`
	StartAt          int        `json:"startAt,omitempty"`
}

type Issue struct {
	ID             string         `json:"id"`
	Key            string         `json:"key"`
	Title          string         `json:"title,omitempty"`
	Status         string         `json:"status,omitempty"`
	URL            string         `json:"url,omitempty"`
	Created        string         `json:"created,omitempty"`
	Updated        string         `json:"updated,omitempty"`
	ResolutionDate string         `json:"resolutionDate,omitempty"`
	DueDate        string         `json:"dueDate,omitempty"`
	Assignee       string         `json:"assignee,omitempty"`
	Reporter       string         `json:"reporter,omitempty"`
	Priority       string         `json:"priority,omitempty"`
	IssueType      string         `json:"issueType,omitempty"`
	ProjectKey     string         `json:"projectKey,omitempty"`
	ProjectName    string         `json:"projectName,omitempty"`
	Labels         []string       `json:"labels,omitempty"`
	Components     []string       `json:"components,omitempty"`
	Resolution     string         `json:"resolution,omitempty"`
	StatusCategory string         `json:"statusCategory,omitempty"`
	ParentKey      string         `json:"parentKey,omitempty"`
	ParentID       string         `json:"parentId,omitempty"`
	EpicKey        string         `json:"epicKey,omitempty"`
	Sprint         string         `json:"sprint,omitempty"`
	FixVersions    []string       `json:"fixVersions,omitempty"`
	Versions       []string       `json:"versions,omitempty"`
	Description    string         `json:"description,omitempty"`
	CustomFields   map[string]any `json:"customFields,omitempty"`
	FieldsRaw      map[string]any `json:"fieldsRaw,omitempty"`
	Changelog      map[string]any `json:"changelog,omitempty"`
}

type SearchIssuesOutput struct {
	Issues []Issue `json:"issues"`
	Total  int     `json:"total"`
}

type Sprint struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	State        string `json:"state"`
	StartDate    string `json:"startDate,omitempty"`
	EndDate      string `json:"endDate,omitempty"`
	CompleteDate string `json:"completeDate,omitempty"`
}

type ListSprintsInput struct {
	Account    AccountRef `json:"account"`
	BoardID    int        `json:"boardId"`
	State      string     `json:"state,omitempty"`
	StartAt    int        `json:"startAt,omitempty"`
	MaxResults int        `json:"maxResults,omitempty"`
}

type ListSprintsOutput struct {
	Sprints    []Sprint `json:"sprints"`
	StartAt    int      `json:"startAt"`
	MaxResults int      `json:"maxResults"`
	Total      int      `json:"total"`
	IsLast     bool     `json:"isLast"`
}

type GetActiveSprintInput struct {
	Account AccountRef `json:"account"`
	BoardID int        `json:"boardId"`
}

type GetActiveSprintOutput struct {
	Sprint Sprint `json:"sprint"`
}

type ListSprintIssuesInput struct {
	Account    AccountRef `json:"account"`
	SprintID   int        `json:"sprintId"`
	JQL        string     `json:"jql,omitempty"`
	Fields     string     `json:"fields,omitempty"`
	StartAt    int        `json:"startAt,omitempty"`
	MaxResults int        `json:"maxResults,omitempty"`
}

type ListSprintIssuesOutput struct {
	Issues     []Issue `json:"issues"`
	StartAt    int     `json:"startAt"`
	MaxResults int     `json:"maxResults"`
	Total      int     `json:"total"`
	IsLast     bool    `json:"isLast"`
}

// CreateMetaInput fetches create metadata for project/issue type.
type CreateMetaInput struct {
	Account    AccountRef `json:"account"`
	ProjectKey string     `json:"projectKey,omitempty"`
	IssueType  string     `json:"issueType,omitempty"`
	Expand     string     `json:"expand,omitempty"`
}

type CreateMetaOutput struct {
	Raw json.RawMessage `json:"raw"`
}

// CreateIssueInput creates a new issue.
type CreateIssueInput struct {
	Account      AccountRef     `json:"account"`
	ProjectKey   string         `json:"projectKey"`
	IssueType    string         `json:"issueType"`
	Summary      string         `json:"summary"`
	Description  string         `json:"description,omitempty"`
	Assignee     string         `json:"assignee,omitempty"`
	Reporter     string         `json:"reporter,omitempty"`
	Priority     string         `json:"priority,omitempty"`
	Labels       []string       `json:"labels,omitempty"`
	Components   []string       `json:"components,omitempty"`
	FixVersions  []string       `json:"fixVersions,omitempty"`
	Versions     []string       `json:"versions,omitempty"`
	DueDate      string         `json:"dueDate,omitempty"`
	ParentKey    string         `json:"parentKey,omitempty"`
	ParentID     string         `json:"parentId,omitempty"`
	Resolution   string         `json:"resolution,omitempty"`
	CustomFields map[string]any `json:"customFields,omitempty"`
}

type CreateIssueOutput struct {
	Issue Issue `json:"issue"`
}

// AddCommentInput adds a comment to an issue.
type AddCommentInput struct {
	Account AccountRef `json:"account"`
	Key     string     `json:"key"`
	Body    string     `json:"body"`
}

type AddCommentOutput struct {
	ID string `json:"id"`
}

// ListCommentsInput lists comments for an issue.
type ListCommentsInput struct {
	Account AccountRef `json:"account"`
	Key     string     `json:"key"`
}

type Comment struct {
	ID     string `json:"id"`
	Body   string `json:"body"`
	Author string `json:"author,omitempty"`
}

type ListCommentsOutput struct {
	Comments []Comment `json:"comments"`
}

// Custom field contexts
type ListCustomFieldContextsInput struct {
	Account AccountRef `json:"account"`
	FieldID string     `json:"fieldId"`
}

type CustomFieldContext struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type ListCustomFieldContextsOutput struct {
	Contexts []CustomFieldContext `json:"contexts"`
}

// Custom field options
type ListCustomFieldOptionsInput struct {
	Account    AccountRef `json:"account"`
	FieldID    string     `json:"fieldId"`
	ContextID  string     `json:"contextId"`
	StartAt    int        `json:"startAt,omitempty"`
	MaxResults int        `json:"maxResults,omitempty"`
}

type CustomFieldOption struct {
	ID    string `json:"id"`
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

type ListCustomFieldOptionsOutput struct {
	Options    []CustomFieldOption `json:"options"`
	IsLast     bool                `json:"isLast,omitempty"`
	StartAt    int                 `json:"startAt,omitempty"`
	MaxResults int                 `json:"maxResults,omitempty"`
	Total      int                 `json:"total,omitempty"`
}

// User search
type ListUsersInput struct {
	Account    AccountRef `json:"account"`
	Query      string     `json:"query"`
	StartAt    int        `json:"startAt,omitempty"`
	MaxResults int        `json:"maxResults,omitempty"`
}

type User struct {
	AccountID   string `json:"accountId,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	Active      bool   `json:"active,omitempty"`
}

type ListUsersOutput struct {
	Users []User `json:"users"`
}

// GetIssueInput fetches a single issue by key.
type GetIssueInput struct {
	Account AccountRef `json:"account"`
	Key     string     `json:"key"`
	Fields  []string   `json:"fields,omitempty"`
}

type GetIssueOutput struct {
	Issue Issue `json:"issue"`
}

// UpdateIssueInput updates fields on an issue.
type UpdateIssueInput struct {
	Account      AccountRef     `json:"account"`
	Key          string         `json:"key"`
	Summary      string         `json:"summary,omitempty"`
	Description  string         `json:"description,omitempty"`
	Assignee     string         `json:"assignee,omitempty"`
	Reporter     string         `json:"reporter,omitempty"`
	Priority     string         `json:"priority,omitempty"`
	Labels       []string       `json:"labels,omitempty"`
	Components   []string       `json:"components,omitempty"`
	FixVersions  []string       `json:"fixVersions,omitempty"`
	Versions     []string       `json:"versions,omitempty"`
	DueDate      string         `json:"dueDate,omitempty"`
	ParentKey    string         `json:"parentKey,omitempty"`
	ParentID     string         `json:"parentId,omitempty"`
	Resolution   string         `json:"resolution,omitempty"`
	CustomFields map[string]any `json:"customFields,omitempty"`
	Fields       map[string]any `json:"fields,omitempty"`
}

type UpdateIssueOutput struct {
	Updated bool `json:"updated"`
}

// TransitionIssueInput transitions an issue to a new status.
type TransitionIssueInput struct {
	Account        AccountRef     `json:"account"`
	Key            string         `json:"key"`
	TransitionID   string         `json:"transitionId,omitempty"`
	TransitionName string         `json:"transitionName,omitempty"`
	Comment        string         `json:"comment,omitempty"`
	Fields         map[string]any `json:"fields,omitempty"`
	CustomFields   map[string]any `json:"customFields,omitempty"`
}

type TransitionIssueOutput struct {
	Transitioned bool   `json:"transitioned"`
	TransitionID string `json:"transitionId,omitempty"`
}

// Watchers
type AddWatcherInput struct {
	Account   AccountRef `json:"account"`
	Key       string     `json:"key"`
	AccountID string     `json:"accountId"`
}

type AddWatcherOutput struct {
	Added bool `json:"added"`
}

type RemoveWatcherInput struct {
	Account   AccountRef `json:"account"`
	Key       string     `json:"key"`
	AccountID string     `json:"accountId"`
}

type RemoveWatcherOutput struct {
	Removed bool `json:"removed"`
}

// Worklogs
type Worklog struct {
	ID               string `json:"id,omitempty"`
	Author           string `json:"author,omitempty"`
	Comment          string `json:"comment,omitempty"`
	Created          string `json:"created,omitempty"`
	Updated          string `json:"updated,omitempty"`
	Started          string `json:"started,omitempty"`
	TimeSpent        string `json:"timeSpent,omitempty"`
	TimeSpentSeconds int    `json:"timeSpentSeconds,omitempty"`
}

type ListWorklogsInput struct {
	Account    AccountRef `json:"account"`
	Key        string     `json:"key"`
	StartAt    int        `json:"startAt,omitempty"`
	MaxResults int        `json:"maxResults,omitempty"`
}

type ListWorklogsOutput struct {
	Worklogs   []Worklog `json:"worklogs"`
	StartAt    int       `json:"startAt,omitempty"`
	MaxResults int       `json:"maxResults,omitempty"`
	Total      int       `json:"total,omitempty"`
}

type AddWorklogInput struct {
	Account          AccountRef `json:"account"`
	Key              string     `json:"key"`
	Comment          string     `json:"comment,omitempty"`
	Started          string     `json:"started,omitempty"`
	TimeSpent        string     `json:"timeSpent,omitempty"`
	TimeSpentSeconds int        `json:"timeSpentSeconds,omitempty"`
}

type AddWorklogOutput struct {
	Worklog Worklog `json:"worklog"`
}

// Bulk create/update
type BulkIssueInput struct {
	ProjectKey   string         `json:"projectKey"`
	IssueType    string         `json:"issueType"`
	Summary      string         `json:"summary"`
	Description  string         `json:"description,omitempty"`
	Assignee     string         `json:"assignee,omitempty"`
	Reporter     string         `json:"reporter,omitempty"`
	Priority     string         `json:"priority,omitempty"`
	Labels       []string       `json:"labels,omitempty"`
	Components   []string       `json:"components,omitempty"`
	FixVersions  []string       `json:"fixVersions,omitempty"`
	Versions     []string       `json:"versions,omitempty"`
	DueDate      string         `json:"dueDate,omitempty"`
	ParentKey    string         `json:"parentKey,omitempty"`
	ParentID     string         `json:"parentId,omitempty"`
	Resolution   string         `json:"resolution,omitempty"`
	CustomFields map[string]any `json:"customFields,omitempty"`
}

type BulkCreateIssuesInput struct {
	Account AccountRef       `json:"account"`
	Issues  []BulkIssueInput `json:"issues"`
}

type BulkCreateIssuesOutput struct {
	Raw json.RawMessage `json:"raw"`
}

type BulkUpdateIssue struct {
	Key          string         `json:"key,omitempty"`
	ID           string         `json:"id,omitempty"`
	Fields       map[string]any `json:"fields,omitempty"`
	CustomFields map[string]any `json:"customFields,omitempty"`
}

type BulkUpdateIssuesInput struct {
	Account AccountRef        `json:"account"`
	Issues  []BulkUpdateIssue `json:"issues"`
}

type BulkUpdateIssuesOutput struct {
	Raw json.RawMessage `json:"raw"`
}

// Delete issue
type DeleteIssueInput struct {
	Account        AccountRef `json:"account"`
	Key            string     `json:"key"`
	DeleteSubtasks bool       `json:"deleteSubtasks,omitempty"`
}

type DeleteIssueOutput struct {
	Deleted bool `json:"deleted"`
}
