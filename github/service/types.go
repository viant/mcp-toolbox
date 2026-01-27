package service

import "github.com/viant/mcp-protocol/extension"

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

type ListOwnerReposInput struct {
	Account Account `json:"account"`
	Owner   string  `json:"owner"`
	PerPage int     `json:"perPage,omitempty" description:"page size (default 30)"`
}
type ListOwnerReposOutput struct {
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

// List path (assets) types — compact contract optimized for LLM usage.
type ListRepoPathInput struct {
	GitTarget
	Path      string   `json:"path"`
	Recursive bool     `json:"recursive,omitempty"`
	Include   []string `json:"include,omitempty"`
	Exclude   []string `json:"exclude,omitempty"`
}

type ListRepoPathOutput struct {
	Ref     string   `json:"ref,omitempty"` // effective ref used (default branch when omitted)
	Paths   []string `json:"paths"`         // repo-relative paths under the requested scope
	Warning string   `json:"warning,omitempty"`
}

type ReadInput struct {
	GitTarget
	Path string `json:"path"`
	// Optional sed-like preview/transform (no repo changes)
	SedScripts       []string `json:"sedScripts,omitempty" description:"sed scripts e.g. s/old/new/g; preview only"`
	MaxEditsPerFile  int      `json:"maxEditsPerFile,omitempty"`
	ApplySedToOutput bool     `json:"applySedToOutput,omitempty" description:"when true and file is text, return transformed text instead of original"`
	// Preview controls and windowing for large files.
	Mode        string `json:"mode,omitempty" description:"preview mode: head (default), tail, signatures"`
	MaxBytes    int    `json:"maxBytes,omitempty" description:"maximum bytes to return when previewing large files"`
	OffsetBytes int    `json:"offsetBytes,omitempty" description:"start offset when continuing a large file"`
	LengthBytes int    `json:"lengthBytes,omitempty" description:"optional byte length window for the selection"`
}
type ReadOutput struct {
	// Content carries binary data when the file is not recognized as UTF-8 text.
	Content []byte `json:"content,omitempty"`
	// Text carries UTF-8 textual content when auto-detected; in this case, Content is omitted.
	Text string `json:"text,omitempty"`
	// TransformedText carries sed-transformed text when sedScripts are provided; original Text is preserved unless ApplySedToOutput=true.
	TransformedText string     `json:"transformedText,omitempty"`
	SedPreview      *SedResult `json:"sedPreview,omitempty"`
	// Size is the original file size in bytes.
	Size int `json:"size,omitempty"`
	// Returned counts bytes emitted in Text/Content after clipping.
	Returned int `json:"returned,omitempty"`
	// Remaining estimates bytes still available past the returned slice.
	Remaining int `json:"remaining,omitempty"`
	// ModeApplied echoes the preview mode when a limit was requested.
	ModeApplied string `json:"modeApplied,omitempty"`
	// Binary indicates that the response content represents binary data.
	Binary bool `json:"binary,omitempty"`
	// Continuation shares pagination hints for follow-up reads.
	Continuation *extension.Continuation `json:"continuation,omitempty"`
}

// GrepFilesInput defines a search + preview (no-apply) request on a repo snapshot.
type GrepFilesInput struct {
	GitTarget
	// Scope
	Path      string   `json:"path"`
	Recursive bool     `json:"recursive,omitempty"`
	Include   []string `json:"include,omitempty"`
	Exclude   []string `json:"exclude,omitempty"`
	// Content filters
	Queries         []string `json:"queries,omitempty"`
	ExcludeQueries  []string `json:"excludeQueries,omitempty"`
	CaseInsensitive bool     `json:"caseInsensitive,omitempty"`
	// Preview shaping
	Mode      string `json:"mode,omitempty"  description:"match mode returns lines around matches"  choice:"head" choice:"match" `
	Bytes     int    `json:"bytes,omitempty"`
	Lines     int    `json:"lines,omitempty"`
	MaxFiles  int    `json:"maxFiles,omitempty"`
	MaxBlocks int    `json:"maxBlocks,omitempty"`
	// Safety/perf
	SkipBinary  bool `json:"skipBinary,omitempty"`
	MaxSize     int  `json:"maxSize,omitempty"`
	Concurrency int  `json:"concurrency,omitempty"`
}

type GrepFilesOutput struct {
	Ref   string        `json:"ref,omitempty"`
	Sha   string        `json:"sha"`
	Stats PreviewStats  `json:"stats"`
	Files []PreviewFile `json:"files,omitempty"`
}

type PreviewStats struct {
	Scanned   int  `json:"scanned"`
	Matched   int  `json:"matched"`
	Truncated bool `json:"truncated,omitempty"`
}

type PreviewFile struct {
	Path     string           `json:"path"`
	Matches  int              `json:"matches,omitempty"`
	Score    float32          `json:"score,omitempty"`
	Snippets []PreviewSnippet `json:"snippets,omitempty"`
	Omitted  int              `json:"omitted,omitempty"`
}

type PreviewSnippet struct {
	Start   int      `json:"start"`
	End     int      `json:"end"`
	Text    string   `json:"text,omitempty"`
	Hits    [][2]int `json:"hits,omitempty"`
	Covered int      `json:"covered,omitempty"`
	Total   int      `json:"total,omitempty"`
	Cut     bool     `json:"cut,omitempty"`
}

type SedResult struct {
	Edits int    `json:"edits"`
	Diff  string `json:"diff,omitempty"`
}

// GrepFilesInput requests finding files with optional sed-like preview (no apply).
// (duplicate type removed)

// (deprecated duplicate preview types removed)
