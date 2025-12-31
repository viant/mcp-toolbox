package service

import (
	"time"
)

type PathKind int

const (
	PathKindUndefined = PathKind(iota)
	PathKindSimple
	PathKindComposite
)

type StartInput struct {
	Driver       string
	Capabilities []string
	Port         int
}

type StartOutput struct {
	Pid           int
	DriverPath    string
	DriverVersion string
	SessionID     string // host:port
}

type StopInput struct {
	Port int
}

type StopOutput struct{}

type OpenSessionInput struct {
	Browser      string
	Capabilities []string
	SessionID    string // host:port
	Remote       string // optional; computed from SessionID if empty
}

type OpenSessionOutput struct{ SessionID string }

type CloseSessionInput struct{ SessionID string }
type CloseSessionOutput struct{ SessionID string }

type WebDriverCallInput struct {
	SessionID string
	Key       string
	PathKind  PathKind
	Call      *MethodCall
}

type WebElementSelector struct {
	By    string
	Value string
	Key   string
}

type WebElementCallInput struct {
	SessionID string
	Selector  *WebElementSelector
	Call      *MethodCall
	PathKind  PathKind
}

type CallOutput struct {
	Result []any
	Data   map[string]any
}

type WebElementCallOutput struct {
	Result      []any
	LookupError string
	Data        map[string]any
}

type NavigationOptions struct {
	TimeoutMs      int
	AutoScrollMs   int
	ScrollDelayMs  int
	StableWindowMs int
	MaxScrollSteps int
	IdleThreshold  int
	IdleWindowMs   int
	IdleMaxWaitMs  int
}

type RunInput struct {
	SessionID   string
	Browser     string
	Remote      string
	Navigation  *NavigationOptions
	Actions     []*Action
	ActionDelay int `json:"actionDelaysMs"`
	Commands    []any
	Expect      any
}

type RunOutput struct {
	SessionID    string
	Data         map[string]any
	LookupErrors []string
	Warnings     []string
}

type Wait struct {
	WaitTimeMs    int
	ThinkTimeMs   int
	IgnoreTimeout bool
	Exit          string
}

type MethodCall struct {
	Wait
	Method     string
	Parameters []any
}

type Action struct {
	Key string
	PathKind
	Selector *WebElementSelector
	Calls    []*MethodCall
}

type CaptureStartInput struct {
	SessionID       string
	SinkURL         string
	FlushIntervalMs int
	MaxBodyBytes    int
	Redact          *bool
	RedactHeaders   []string
	EnableConsole   *bool
	EnableNetwork   *bool
	IncludeBodies   *bool
}

type CaptureStartOutput struct {
	SessionID string
	Enabled   bool
	Warning   string
}

type CaptureStopInput struct{ SessionID string }

type CaptureStopOutput struct {
	SessionID string
	Summary   *CaptureSummary
}

type CaptureStatusInput struct{ SessionID string }
type CaptureStatusOutput struct {
	SessionID string
	Summary   *CaptureSummary
}

type CaptureClearInput struct{ SessionID string }
type CaptureClearOutput struct{ SessionID string }

type CaptureExportInput struct {
	SessionID      string
	MaxEntries     int
	IncludeConsole *bool
	IncludeNetwork *bool
}

type CaptureExportOutput struct {
	SessionID string
	Summary   *CaptureSummary
	Console   []*ConsoleEntry
	Network   []*NetworkTransaction
}

type ScreenshotInput struct {
	SessionID string
	// DestURL is an optional AFS URL to write the PNG to (e.g. file:///tmp/screenshot.png).
	// If empty, the PNG is returned as base64 in the response.
	DestURL string
	// FullPage uses Chrome/Edge CDP Page.captureScreenshot best-effort; falls back to viewport screenshot if not available.
	FullPage bool
	// Selector captures an element screenshot if provided.
	Selector *WebElementSelector
	// ScrollIntoView applies to element screenshots (default true).
	ScrollIntoView *bool
	// MaxWaitMs controls element lookup wait time (default 10000).
	MaxWaitMs int
}

type ScreenshotOutput struct {
	SessionID string
	DestURL   string
	Bytes     int
	Encoding  string // "base64" when Data is set
	Data      string // base64 PNG when DestURL is empty
}

type DriverInstallInput struct {
	// Driver is "chromedriver" or "geckodriver" (default "chromedriver").
	Driver string
	// InstallDir overrides the service install dir (when empty, service default is used).
	InstallDir string
	// Force re-downloads even if the binary already exists (i.e. "update").
	Force bool
}

type DriverInstallOutput struct {
	Driver      string
	InstallDir  string
	DriverPath  string
	Version     string
	ArtifactURL string
	Downloaded  bool
}

type GetSourceInput struct {
	SessionID string
	// DestURL is an optional AFS URL to write the HTML to (e.g. file:///tmp/source.html).
	// If empty, the HTML is returned in the response.
	DestURL string
	// MaxBytes truncates the HTML response (default 0 = no limit).
	MaxBytes int
}

type GetSourceOutput struct {
	SessionID string
	DestURL   string
	Bytes     int
	Truncated bool
	Encoding  string // "utf-8" when Data is set
	Data      string // HTML when DestURL is empty
}

type GetDOMInput struct {
	SessionID string
	// Format can be:
	// - "outerHTML" (default): returns documentElement.outerHTML
	// - "snapshot": Chrome/Edge only (CDP DOMSnapshot.captureSnapshot)
	Format string
	// DestURL is an optional AFS URL to write the result to:
	// - outerHTML: writes HTML
	// - snapshot: writes JSON
	// If empty, the result is returned in the response.
	DestURL string
	// MaxBytes truncates outerHTML response (default 0 = no limit). Ignored for snapshot when returned structured.
	MaxBytes int
}

type GetDOMOutput struct {
	SessionID string
	Format    string
	DestURL   string

	Bytes     int
	Truncated bool

	Encoding  string // "utf-8" when OuterHTML is set
	OuterHTML string
	Snapshot  map[string]any
}

type SessionsInput struct {
	// IncludeAll includes sessions that exist but are not currently open.
	IncludeAll bool
}

type SessionInfo struct {
	SessionID string
	Browser   string
	Remote    string

	DriverPath    string
	DriverVersion string
	Capabilities  []string

	Open           bool
	CaptureEnabled bool
}

type SessionsOutput struct {
	Sessions []*SessionInfo
}

type EvalJSInput struct {
	SessionID string

	// Script is JavaScript source.
	Script string
	// Args are passed to the script as arguments.
	Args []any

	// Async uses ExecuteScriptAsync when available.
	Async bool
	// TimeoutMs is best-effort and applies to async execution when supported by the driver.
	TimeoutMs int

	// DestURL optionally writes the result as JSON via viant/afs (e.g. file:///tmp/eval.json).
	// If set, Result is omitted from the response.
	DestURL string
}

type EvalJSOutput struct {
	SessionID string
	DestURL   string
	Bytes     int

	Result any
}

// Locator is a Playwright-inspired element query that can be resolved by the service.
// It is intentionally small and maps to WebDriver + JS filtering as needed.
//
// Resolution order (rough):
// 1) base selector (CSS/XPath) if present
// 2) role/name/text filters applied by JS when needed
type Locator struct {
	// CSS is an optional CSS selector to narrow down candidates.
	CSS string `json:"css,omitempty"`
	// XPath is an optional XPath selector to narrow down candidates.
	XPath string `json:"xpath,omitempty"`

	// Role matches aria role (explicit role attr only for now).
	Role string `json:"role,omitempty"`
	// Name matches accessible-ish name (uses aria-label, aria-labelledby, and element text).
	Name string `json:"name,omitempty"`
	// Text matches visible-ish text (uses innerText when available).
	Text string `json:"text,omitempty"`
	// Exact controls Text/Name exactness (defaults false = contains).
	Exact bool `json:"exact,omitempty"`

	// TestID matches data-testid attribute by default (configurable on server later).
	TestID string `json:"testID,omitempty"`

	// Within optionally scopes the search to a container selector (CSS or XPath).
	Within *Locator `json:"within,omitempty"`

	// Composition:
	// - All: intersection (element must match all locators)
	// - Any: union (element can match any locator)
	// - Not: exclusion (exclude elements matching this locator)
	All []*Locator `json:"all,omitempty"`
	Any []*Locator `json:"any,omitempty"`
	Not *Locator   `json:"not,omitempty"`
}

type Rect struct {
	X      float64 `json:"x,omitempty"`
	Y      float64 `json:"y,omitempty"`
	Width  float64 `json:"width,omitempty"`
	Height float64 `json:"height,omitempty"`
}

type FindMatch struct {
	// Selector is a best-effort generated CSS selector for follow-up calls.
	Selector string            `json:"selector,omitempty"`
	Tag      string            `json:"tag,omitempty"`
	Text     string            `json:"text,omitempty"`
	Role     string            `json:"role,omitempty"`
	Name     string            `json:"name,omitempty"`
	Attrs    map[string]string `json:"attrs,omitempty"`
	Rect     *Rect             `json:"rect,omitempty"`
	Visible  bool              `json:"visible,omitempty"`
}

type FindInput struct {
	SessionID string `json:"sessionID,omitempty"`

	// Locator describes what to find.
	Locator *Locator `json:"locator,omitempty"`

	// Key stores the output matches under Data[key] when set.
	Key string `json:"key,omitempty"`

	// MaxWaitMs controls auto-wait for matches (default 10000).
	MaxWaitMs int `json:"maxWaitMs,omitempty"`
	// PollMs controls polling interval (default 200).
	PollMs int `json:"pollMs,omitempty"`

	// MinMatches waits until at least N matches are found (default 1).
	MinMatches int `json:"minMatches,omitempty"`
	// MaxMatches limits returned matches (default 20).
	MaxMatches int `json:"maxMatches,omitempty"`
	// Strict fails if matches != 1.
	Strict bool `json:"strict,omitempty"`
	// VisibleOnly filters to displayed elements only.
	VisibleOnly bool `json:"visibleOnly,omitempty"`
}

type FindOutput struct {
	SessionID string
	Matches   []*FindMatch   `json:"matches,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	Warning   string         `json:"warning,omitempty"`
}

type ClickInput struct {
	SessionID   string   `json:"sessionID,omitempty"`
	Locator     *Locator `json:"locator,omitempty"`
	TimeoutMs   int      `json:"timeoutMs,omitempty"`
	Strict      bool     `json:"strict,omitempty"`
	VisibleOnly bool     `json:"visibleOnly,omitempty"`
}

type ClickOutput struct {
	SessionID string     `json:"sessionID,omitempty"`
	Match     *FindMatch `json:"match,omitempty"`
}

type FillInput struct {
	SessionID   string   `json:"sessionID,omitempty"`
	Locator     *Locator `json:"locator,omitempty"`
	Text        string   `json:"text,omitempty"`
	ClearFirst  bool     `json:"clearFirst,omitempty"`
	TimeoutMs   int      `json:"timeoutMs,omitempty"`
	Strict      bool     `json:"strict,omitempty"`
	VisibleOnly bool     `json:"visibleOnly,omitempty"`
}

type FillOutput struct {
	SessionID string     `json:"sessionID,omitempty"`
	Match     *FindMatch `json:"match,omitempty"`
}

type PressInput struct {
	SessionID   string   `json:"sessionID,omitempty"`
	Locator     *Locator `json:"locator,omitempty"`
	Key         string   `json:"key,omitempty"`
	TimeoutMs   int      `json:"timeoutMs,omitempty"`
	Strict      bool     `json:"strict,omitempty"`
	VisibleOnly bool     `json:"visibleOnly,omitempty"`
}

type PressOutput struct {
	SessionID string     `json:"sessionID,omitempty"`
	Match     *FindMatch `json:"match,omitempty"`
}

type CaptureSummary struct {
	StartedAt         time.Time
	RequestsInFlight  int
	RequestsCompleted int
	ConsoleEntries    int
	Errors            []string
}

type ConsoleEntry struct {
	Timestamp time.Time
	Level     string
	Message   string
}

type CapturedBody struct {
	Encoding  string
	Data      string
	Truncated bool
}

type NetworkTransaction struct {
	RequestID string

	URL    string
	Method string

	RequestHeaders map[string]any
	RequestBody    *CapturedBody
	ResourceType   string
	Initiator      map[string]any

	StartTimestamp float64
	EndTimestamp   float64
	DurationMs     int64

	ErrorText       string
	WasCanceled     bool
	EncodedDataSize int64

	Status          int
	StatusText      string
	MimeType        string
	ResponseHeaders map[string]any
	ResponseBody    *CapturedBody
}
