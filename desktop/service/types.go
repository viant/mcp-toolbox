package service

type Point struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type Size struct {
	W int `json:"w"`
	H int `json:"h"`
}

type Rect struct {
	X int `json:"x"`
	Y int `json:"y"`
	W int `json:"w"`
	H int `json:"h"`
}

type InfoInput struct{}

type InfoOutput struct {
	GOOS   string  `json:"goos"`
	GOARCH string  `json:"goarch"`
	Screen Size    `json:"screen"`
	Mouse  Point   `json:"mouse"`
	Scale  float64 `json:"scale"`
}

type MouseMoveInput struct {
	X      int   `json:"x"`
	Y      int   `json:"y"`
	Smooth *bool `json:"smooth"`

	// For moveSmooth only.
	Low       float64 `json:"low"`
	High      float64 `json:"high"`
	DelayMs   int     `json:"delayMs"`
	UseSmooth bool    `json:"useSmooth"`

	Timing
}

type MouseMoveOutput struct {
	Mouse Point `json:"mouse"`
}

type MouseClickInput struct {
	Button string `json:"button"`
	Double bool   `json:"double"`

	X *int `json:"x"`
	Y *int `json:"y"`

	// Down can be "down" or "up" to press/release without a full click.
	Down string `json:"down"`

	Timing
}

type MouseClickOutput struct {
	Mouse Point `json:"mouse"`
}

type ScrollInput struct {
	X       int `json:"x"`
	Y       int `json:"y"`
	DelayMs int `json:"delayMs"`

	Timing
}

type ScrollOutput struct{}

type KeyTapInput struct {
	Key       string   `json:"key"`
	Modifiers []string `json:"modifiers"`
	Pid       int      `json:"pid"`

	Timing
}

type KeyTapOutput struct{}

type TypeInput struct {
	Text string `json:"text"`
	Pid  int    `json:"pid"`

	Timing
}

type TypeOutput struct{}

type ScreenshotInput struct {
	DestURL   string `json:"destURL"`
	Rect      *Rect  `json:"rect"`
	DisplayID *int   `json:"displayId"`

	Timing
}

type ScreenshotOutput struct {
	DestURL   string `json:"destURL"`
	Bytes     int    `json:"bytes"`
	Encoding  string `json:"encoding,omitempty"`
	Data      string `json:"data,omitempty"`
	MimeType  string `json:"mimeType,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

type RunInput struct {
	Commands    []string `json:"commands"`
	ActionDelay int      `json:"actionDelaysMs"`
	DisplayID   *int     `json:"displayId"`
	Timing
}

type RunAction struct {
	Index   int    `json:"index"`
	Command string `json:"command"`
	Error   string `json:"error,omitempty"`
}

type RunOutput struct {
	Data    map[string]any `json:"data"`
	Actions []RunAction    `json:"actions"`
}

type ListWindowsInput struct {
	TitleContains     string `json:"titleContains"`
	Limit             int    `json:"limit"`
	IncludeEmptyTitle bool   `json:"includeEmptyTitle"`
}

type WindowInfo struct {
	Pid    int    `json:"pid"`
	Handle int64  `json:"handle"`
	Title  string `json:"title"`
	Bounds Rect   `json:"bounds"`
	Active bool   `json:"active"`
}

type ListWindowsOutput struct {
	ActivePid int          `json:"activePid"`
	Windows   []WindowInfo `json:"windows"`
}

type WindowTarget struct {
	// Kind is "pid" or "handle".
	Kind string `json:"kind" choice:"pid" choice:"handle"`
	// ID is either PID or OS-specific handle (HWND/XID).
	ID int64 `json:"id"`
}

type ActivateWindowInput struct {
	Target WindowTarget `json:"target"`
}

type ActivateWindowOutput struct{}

type WindowBoundsInput struct {
	Target WindowTarget `json:"target"`
	// Client returns client bounds instead of outer bounds.
	Client bool `json:"client"`
}

type WindowBoundsOutput struct {
	Bounds Rect `json:"bounds"`
}

type WindowStateInput struct {
	Target WindowTarget `json:"target"`
	// State=true applies the state (min/max); State=false attempts to restore.
	State bool `json:"state"`
}

type WindowStateOutput struct{}

type CloseWindowInput struct {
	Target WindowTarget `json:"target"`
}

type CloseWindowOutput struct{}

type SetForegroundWindowInput struct {
	HWND int64 `json:"hwnd"`
}

type SetForegroundWindowOutput struct {
	OK bool `json:"ok"`
}

type SendWindowMsgInput struct {
	HWND   int64  `json:"hwnd"`
	Msg    uint32 `json:"msg"`
	WParam uint64 `json:"wParam"`
	LParam uint64 `json:"lParam"`
}

type SendWindowMsgOutput struct {
	Result uint64 `json:"result"`
}

type Timing struct {
	MouseSleepMs *int `json:"mouseSleepMs"`
	KeySleepMs   *int `json:"keySleepMs"`
}

type ReadClipboardInput struct {
	// Format can be "auto"|"text"|"html"|"image" (default: "auto").
	Format string `json:"format" choice:"auto" choice:"text" choice:"html" choice:"image"`
	Timing
}

type ReadClipboardOutput struct {
	MimeType string `json:"mimeType"`
	Encoding string `json:"encoding,omitempty"` // base64 for binary, empty for text
	Data     string `json:"data,omitempty"`     // base64 for binary
	Text     string `json:"text,omitempty"`     // for text/plain and text/html
}

type WriteClipboardInput struct {
	MimeType string `json:"mimeType" choice:"text/plain" choice:"text/html" choice:"image/png"`
	// Text is used for text/plain and text/html.
	Text string `json:"text"`
	// Data is base64 for image/png.
	Encoding string `json:"encoding,omitempty" choice:"base64"`
	Data     string `json:"data,omitempty"`
	Timing
}

type WriteClipboardOutput struct{}

type SaveClipboardInput struct {
	// DestURL is an AFS URL (typically file://...) to write the clipboard contents to.
	// If empty, a default temp file path is chosen based on detected mime type.
	DestURL string `json:"destURL"`
	// Format selects which clipboard format to save ("auto" prefers image/html/text).
	Format string `json:"format" choice:"auto" choice:"text" choice:"html" choice:"image"`
	Timing
}

type SaveClipboardOutput struct {
	DestURL   string `json:"destURL"`
	MimeType  string `json:"mimeType"`
	Bytes     int    `json:"bytes"`
	Encoding  string `json:"encoding,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

type KeyToggleInput struct {
	Key       string   `json:"key"`
	Down      string   `json:"down" choice:"down" choice:"up"` // "down"|"up"
	Modifiers []string `json:"modifiers"`
	Pid       int      `json:"pid"`
	Timing
}

type KeyToggleOutput struct{}

type MouseToggleInput struct {
	Button string `json:"button"`
	Down   string `json:"down" choice:"down" choice:"up"` // "down"|"up"
	Timing
}

type MouseToggleOutput struct{}

type DragSmoothInput struct {
	X      int    `json:"x"`
	Y      int    `json:"y"`
	Button string `json:"button"`
	Timing
}

type DragSmoothOutput struct{}

type MoveRelativeInput struct {
	DX int `json:"dx"`
	DY int `json:"dy"`
	Timing
}

type MoveRelativeOutput struct{}

type ScrollDirInput struct {
	Amount    int    `json:"amount"`
	Direction string `json:"direction" choice:"up" choice:"down" choice:"left" choice:"right"`
	Timing
}

type ScrollDirOutput struct{}

type ScrollSmoothInput struct {
	ToY     int `json:"toY"`
	Num     int `json:"num"`
	SleepMs int `json:"sleepMs"`
	ToX     int `json:"toX"`
	Timing
}

type ScrollSmoothOutput struct{}

type StartProcessInput struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Cwd       string            `json:"cwd"`
	Env       map[string]string `json:"env"`
	Wait      bool              `json:"wait"`
	TimeoutMs int               `json:"timeoutMs"`
	Timing
}

type StartProcessOutput struct {
	Pid      int    `json:"pid"`
	Started  bool   `json:"started"`
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output"`
}

type GetPixelColorInput struct {
	X         int  `json:"x"`
	Y         int  `json:"y"`
	DisplayID *int `json:"displayId"`
	Timing
}

type GetPixelColorOutput struct {
	X   int    `json:"x"`
	Y   int    `json:"y"`
	Hex string `json:"hex"`
}

type SamplePixelsInput struct {
	Rect       Rect `json:"rect"`
	StepX      int  `json:"stepX"`
	StepY      int  `json:"stepY"`
	MaxSamples int  `json:"maxSamples"`
	DisplayID  *int `json:"displayId"`
	Timing
}

type PixelSample struct {
	X   int    `json:"x"`
	Y   int    `json:"y"`
	Hex string `json:"hex"`
}

type SamplePixelsOutput struct {
	Samples []PixelSample `json:"samples"`
}

type FindImageInput struct {
	TemplateURL string  `json:"templateURL"`
	Rect        *Rect   `json:"rect"`
	DisplayID   *int    `json:"displayId"`
	MaxResults  int     `json:"maxResults"`
	Threshold   float64 `json:"threshold"`
	Step        int     `json:"step"`
	MaxTimeMs   int     `json:"maxTimeMs"`
	Timing
}

type ImageMatch struct {
	X     int     `json:"x"`
	Y     int     `json:"y"`
	W     int     `json:"w"`
	H     int     `json:"h"`
	Score float64 `json:"score"`
}

type FindImageOutput struct {
	Matches []ImageMatch `json:"matches"`
}

type ClickImageInput struct {
	TemplateURL string  `json:"templateURL"`
	Rect        *Rect   `json:"rect"`
	DisplayID   *int    `json:"displayId"`
	Button      string  `json:"button"`
	Double      bool    `json:"double"`
	Threshold   float64 `json:"threshold"`
	Step        int     `json:"step"`
	MaxTimeMs   int     `json:"maxTimeMs"`
	Timing
}

type ClickImageOutput struct {
	Match *ImageMatch `json:"match"`
}

type DisplayInfoInput struct{}

type DisplayInfoOutput struct {
	DisplayID   int     `json:"displayId"`
	MainID      int     `json:"mainId"`
	NumDisplays int     `json:"numDisplays"`
	Scale       float64 `json:"scale"`
	Rects       []Rect  `json:"rects"`
}

type SetDisplayInput struct {
	DisplayID int `json:"displayId"`
}

type SetDisplayOutput struct {
	DisplayID int `json:"displayId"`
}

type ConvertCoordsInput struct {
	Mode      string  `json:"mode" choice:"logicalToPhysical" choice:"physicalToLogical"`
	DisplayID *int    `json:"displayId"`
	Factor    float64 `json:"factor"`
	X         int     `json:"x"`
	Y         int     `json:"y"`
	W         int     `json:"w"`
	H         int     `json:"h"`
}

type ConvertCoordsOutput struct {
	Factor float64 `json:"factor"`
	X      int     `json:"x"`
	Y      int     `json:"y"`
	W      int     `json:"w"`
	H      int     `json:"h"`
}

type TypeIntoWindowInput struct {
	TitleContains string `json:"titleContains"`
	Text          string `json:"text"`
	Activate      *bool  `json:"activate"`
	DelayMs       int    `json:"delayMs"`
	Timing
}

type TypeIntoWindowOutput struct {
	Pid   int    `json:"pid"`
	Title string `json:"title"`
}

type FindTextInput struct {
	Text       string `json:"text"`
	Rect       *Rect  `json:"rect"`
	Lang       string `json:"lang"`
	MaxResults int    `json:"maxResults"`
	Timing
}

type TextBox struct {
	Text string `json:"text"`
	Rect Rect   `json:"rect"`
}

type FindTextOutput struct {
	Boxes []TextBox `json:"boxes"`
}

type ClickTextInput struct {
	Text    string `json:"text"`
	Rect    *Rect  `json:"rect"`
	Lang    string `json:"lang"`
	Button  string `json:"button"`
	Double  bool   `json:"double"`
	DelayMs int    `json:"delayMs"`
	Timing
}

type ClickTextOutput struct {
	Box *TextBox `json:"box"`
}

type ClickTextThenTypeInput struct {
	Text              string `json:"text"`
	TypeText          string `json:"typeText"`
	Rect              *Rect  `json:"rect"`
	Lang              string `json:"lang"`
	Button            string `json:"button"`
	Double            bool   `json:"double"`
	AfterClickDelayMs int    `json:"afterClickDelayMs"`
	Timing
}

type ClickTextThenTypeOutput struct {
	Box *TextBox `json:"box"`
}
