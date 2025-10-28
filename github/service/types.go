package service

type Account struct {
	Alias  string `json:"alias" description:"account name"`
	Domain string `json:"domain,omitempty" description:"GitHub host (default github.com)"`
}

type RepoRef struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

type Repo struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullName string `json:"fullName"`
}
type Issue struct {
	ID     int64  `json:"id"`
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
}
type PullRequest struct {
	ID     int64  `json:"id"`
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
}
type Comment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	User      string `json:"user"`
	CreatedAt string `json:"createdAt"`
}

type ListReposInput struct {
	Account     Account `json:"account"`
	Visibility  string  `json:"visibility,omitempty" description:"all|public|private"`
	Affiliation string  `json:"affiliation,omitempty" description:"owner,collaborator,organization_member (comma-separated)"`
	PerPage     int     `json:"perPage,omitempty" description:"page size (default 30)"`
}
type ListReposOutput struct {
	Repos []Repo `json:"repos,omitempty"`
}

type ListRepoIssuesInput struct {
	GitTarget
	State string `json:"state,omitempty" description:"open|closed|all"`
}
type ListRepoIssuesOutput struct {
	Issues []Issue `json:"issues,omitempty"`
}

type ListRepoPRsInput struct {
	GitTarget
	State string `json:"state,omitempty" description:"open|closed|all"`
}
type ListRepoPRsOutput struct {
	Pulls []PullRequest `json:"pulls,omitempty"`
}

type CreateIssueInput struct {
	GitTarget
	Title     string   `json:"title"`
	Body      string   `json:"body,omitempty"`
	Labels    []string `json:"labels,omitempty" description:"repeated"`
	Assignees []string `json:"assignees,omitempty" description:"repeated"`
}
type CreateIssueOutput struct {
	Issue Issue `json:"issue"`
}

type CreatePRInput struct {
	GitTarget
	Title string `json:"title"`
	Body  string `json:"body,omitempty"`
	Head  string `json:"head" description:"branch or user:branch"`
	Base  string `json:"base" description:"target branch"`
	Draft bool   `json:"draft,omitempty"`
}
type CreatePROutput struct {
	Pull PullRequest `json:"pull"`
}

type AddCommentInput struct {
	GitTarget
	IssueNumber int    `json:"issueNumber"`
	Body        string `json:"body"`
}
type AddCommentOutput struct {
	Comment Comment `json:"comment"`
}

type ListCommentsInput struct {
	GitTarget
	IssueNumber int `json:"issueNumber"`
}
type ListCommentsOutput struct {
	Comments []Comment `json:"comments,omitempty"`
}

type SearchIssuesInput struct {
	GitTarget
	Query   string `json:"query"`
	PerPage int    `json:"perPage,omitempty"`
}
type SearchIssuesOutput struct {
	Issues []Issue `json:"issues,omitempty"`
}

// Checkout repo types
type CheckoutRepoInput struct {
	GitTarget
	Branch  string `json:"branch,omitempty"`
	Commit  string `json:"commit,omitempty"`
	DestDir string `json:"destDir,omitempty"`
	Depth   int    `json:"depth,omitempty"`
}
type CheckoutRepoOutput struct {
	Path       string `json:"path"`
	CheckedOut string `json:"checkedOut"`
	WasCloned  bool   `json:"wasCloned"`
}

// List path (assets) types
type ListRepoInput struct {
	GitTarget
	Path        string   `json:"path"`
	Recursive   bool     `json:"recursive,omitempty" description:"traverse directories recursively"`
	Contains    string   `json:"contains,omitempty" description:"return only entries whose name or path contains this substring (traversal unaffected)"`
	Concurrency int      `json:"concurrency,omitempty" description:"number of concurrent directory fetches (default 6)"`
	Include     []string `json:"include,omitempty" description:"glob patterns to include (e.g., ['*.go','*.sql'])"`
	Exclude     []string `json:"exclude,omitempty" description:"glob patterns to exclude (e.g., ['*_test.go','**/vendor/**'])"`
}
type AssetItem struct {
	Type string `json:"type"` // file|dir
	Name string `json:"name"`
	Path string `json:"path"`
	Size int    `json:"size"`
	Sha  string `json:"sha"`
}
type ListRepoOutput struct {
	Items []AssetItem `json:"items"`
}

type DownloadInput struct {
	GitTarget
	Path string `json:"path"`
}
type DownloadOutput struct {
    // Content carries binary data when the file is not recognized as UTF-8 text.
    Content []byte `json:"content,omitempty"`
    // Text carries UTF-8 textual content when auto-detected; in this case, Content is omitted.
    Text    string `json:"text,omitempty"`
}
