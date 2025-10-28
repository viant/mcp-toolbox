package graph

// Minimal types for tool I/O

type Account struct {
	// Alias identifies a stored account (e.g. "work", "personal").
	Alias    string `json:"alias" description:"account name"`
	TenantID string `json:"-" internal:"true"`
}

type Message struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	From    string `json:"from,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

type SendEmailInput struct {
	Account    Account  `json:"account"`
	To         []string `json:"to"`
	Subject    string   `json:"subject"`
	BodyText   string   `json:"bodyText,omitempty"`
	BodyHTML   string   `json:"bodyHtml,omitempty"`
	Importance string   `json:"importance,omitempty"` // Low, Normal, High
}

type ListMailInput struct {
    Account  Account `json:"account"`
    Top      int     `json:"top,omitempty" description:"number of messages to return"`
    // Optional ISO8601 (RFC3339) date-time filters on received time.
    SinceISO string  `json:"sinceISO,omitempty" description:"receivedDateTime >= this timestamp (inclusive)"`
    UntilISO string  `json:"untilISO,omitempty" description:"receivedDateTime <= this timestamp (inclusive)"`
    // Advanced OData options. If set, these override the derived filters/order from the fields above.
    Filter  string   `json:"filter,omitempty" description:"OData $filter expression (e.g., receivedDateTime ge 2025-01-01T00:00:00Z and from/emailAddress/address eq 'alice@example.com')"`
    OrderBy []string `json:"orderBy,omitempty" description:"OData $orderby fields (e.g., ['receivedDateTime DESC'])"`
}

type ListMailOutput struct {
    Messages []Message `json:"messages,omitempty"`
}

type CalendarEvent struct {
	ID        string `json:"id"`
	Subject   string `json:"subject"`
	StartISO  string `json:"startISO"`
	EndISO    string `json:"endISO"`
	Location  string `json:"location,omitempty"`
	Organizer string `json:"organizer,omitempty"`
}

type ListEventsInput struct {
    Account Account `json:"account"`
    // List events between now and now+DaysAhead (default 7).
    DaysAhead int `json:"daysAhead,omitempty"`
    // Advanced OData options for filtering/sorting events.
    Filter  string   `json:"filter,omitempty" description:"OData $filter for events (e.g., start/dateTime ge 2025-01-01T00:00:00Z)"`
    OrderBy []string `json:"orderBy,omitempty" description:"OData $orderby fields (e.g., ['start/dateTime DESC'])"`
}

type ListEventsOutput struct {
    Events []CalendarEvent `json:"events,omitempty"`
}

type CreateEventInput struct {
	Account   Account  `json:"account"`
	Subject   string   `json:"subject"`
	StartISO  string   `json:"startISO"`
	EndISO    string   `json:"endISO"`
	TimeZone  string   `json:"timeZone,omitempty"`
	Location  string   `json:"location,omitempty"`
	Attendees []string `json:"attendees,omitempty"`
	BodyText  string   `json:"bodyText,omitempty"`
}

type Task struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status,omitempty"`
}

type ListTasksInput struct {
    Account Account `json:"account"`
    Top     int     `json:"top,omitempty"`
    // Advanced OData options for filtering/sorting tasks.
    Filter  string   `json:"filter,omitempty" description:"OData $filter for tasks (applied per list)"`
    OrderBy []string `json:"orderBy,omitempty" description:"OData $orderby fields for tasks (applied per list)"`
}

type ListTasksOutput struct {
    Tasks []Task `json:"tasks,omitempty"`
}

type CreateTaskInput struct {
	Account  Account `json:"account"`
	Title    string  `json:"title"`
	BodyText string  `json:"bodyText,omitempty"`
	DueISO   string  `json:"dueISO,omitempty"`
}
